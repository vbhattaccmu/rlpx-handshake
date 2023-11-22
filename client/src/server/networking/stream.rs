//! This module hosts the core methods associated to completing the handshake with an outbound message
//! with the recipient after an `Ack` is received.

use bytes::BytesMut;
use futures::SinkExt;
use rlp::{Rlp, RlpStream};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::fmt::Debug;
use tokio_stream::StreamExt;

use crate::{error::HandshakeError, server::networking::*, types::*, utilities::pubkey2id};

#[allow(unused)]
#[derive(Debug)]
pub struct Peer<Io> {
    stream: MessageStream<Io>,
    client_version: String,
    port: u16,
    id: RecipientId,
    remote_id: RecipientId,
}

impl<Io> Peer<Io>
where
    Io: Transport,
{
    /// Utility to send and recv messages to/from recipient after auth-ack phase is complete
    /// initiator sends its first encrypted frame containing the initiator Hello message
    /// Formulations taken from source [RLPx protocol]: https://hackmd.io/@Nhlanhla/SJv3wnhMK
    pub async fn communicate(
        mut transport: MessageStream<Io>,
        secret_key: SecretKey,
        protocol_version: ProtocolVersion,
        client_version: String,
        port: u16,
    ) -> Result<OutboundMessage, HandshakeError> {
        let public_key = PublicKey::from_secret_key(&Secp256k1::new(), &secret_key);
        let id = pubkey2id(&public_key);

        println!("Connecting to recipient: {:02x}", transport.remote_id());

        // Prepare message for recipient
        let hello = OutboundMessage {
            port,
            id,
            protocol_version: (protocol_version as usize),
            client_version: client_version.clone(),
        };

        // Serialize message following RLP
        // First byte reserved for message id
        let mut outbound_hello_msg = BytesMut::new();
        outbound_hello_msg = {
            let mut buf = RlpStream::new_with_buffer(outbound_hello_msg);
            buf.append(&0_usize);
            buf.out()
        };
        outbound_hello_msg = {
            let mut buf = RlpStream::new_with_buffer(outbound_hello_msg);
            buf.append(&hello);
            buf.out()
        };

        println!("  ");
        println!(
            "Encoded outbound hello message: {}",
            hex::encode(&outbound_hello_msg)
        );

        // Send message to recipient
        transport
            .send(outbound_hello_msg.freeze())
            .await
            .map_err(|_| HandshakeError::CommFailure)?;

        // Retrieve response from recipient
        let hello = transport.try_next().await?;
        let hello = hello.ok_or_else(|| HandshakeError::CommFailure)?;

        println!("  ");
        println!("Receiving hello message from recipient: {:02x?}", hello);

        // Assert if message id is correct
        let message_id_rlp_stream: Rlp<'_> = Rlp::new(&hello[0..1]);
        let message_id = message_id_rlp_stream
            .as_val::<usize>()
            .map_err(|_| HandshakeError::CommFailure)?;

        if message_id != 0_usize {
            return Err(HandshakeError::DeserializationFailure);
        }

        // Deserialize payload to get back response from recipient
        let payload = &hello[1..];
        let deserialzied_message = Rlp::new(payload)
            .as_val::<OutboundMessage>()
            .map_err(|_| HandshakeError::DeserializationFailure)?;

        println!("  ");
        println!("Deserialized hello message: {:?}", deserialzied_message);

        Ok(deserialzied_message)
    }
}
