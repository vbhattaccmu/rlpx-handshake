//! A helper module for creating and managing codec for exchanging auth-ack
//! between initiator and recipient.
//! The codec implements a state machine to decode incoming data and transition
//! between different states of the handshake between the peers.

use bytes::{Bytes, BytesMut};
use futures::{ready, Sink, SinkExt};
use secp256k1::SecretKey;
use std::{
    fmt::Debug,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio_stream::*;
use tokio_util::codec::*;

use crate::{
    error::HandshakeError,
    server::{initiator::Initiator, networking::*},
    types::RecipientId,
};

/// Tokio codec for Initiator
#[derive(Debug)]
pub struct Codec {
    /// An instance of an Initiator.
    initiator: Initiator,
    /// Current InitiatorState
    state: InitiatorState,
}

/// Current Initiator state of a connection between initiator and recipient.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitiatorState {
    Auth,
    Ack,
    Header,
    Body,
}

/// Raw ingress values for the Initiator handshake protocol
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngressInitiatorValue {
    AuthReceive(RecipientId),
    Ack,
    Message(Bytes),
}

/// `Initiator` message stream over TCP exchanging raw bytes
#[derive(Debug)]
pub struct MessageStream<Io> {
    pub stream: Framed<Io, Codec>,
    pub remote_id: RecipientId,
}

/// Raw egress values for the Initiator handshake protocol
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EgressInitiatorValue {
    Auth,
    Ack,
    Message(Bytes),
}

impl Codec {
    /// Create a new initiator codec using the given secret key and the recipient's remote public  id
    pub fn new_client(
        secret_key: SecretKey,
        remote_id: RecipientId,
    ) -> Result<Self, HandshakeError> {
        Ok(Self {
            initiator: Initiator::new_client(secret_key, remote_id)?,
            state: InitiatorState::Auth,
        })
    }
}

/// impl for Decoding of frames exchanged between initiator and recipient.
/// The state machine is responsible for decoding frames exchanged between
/// an initiator and a recipient. It processes the incoming datain a loop
/// and transitions between different states based on the current state of the handshake.
impl Decoder for Codec {
    type Item = IngressInitiatorValue;
    type Error = io::Error;
    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            match self.state {
                InitiatorState::Auth => {
                    if buf.len() < 2 {
                        return Ok(None);
                    }

                    let payload_size = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                    let total_size = payload_size + 2;

                    if buf.len() < total_size {
                        return Ok(None);
                    }

                    self.initiator.commit_auth(&mut *buf.split_to(total_size))?;
                    self.state = InitiatorState::Header;
                    return Ok(Some(IngressInitiatorValue::AuthReceive(
                        self.initiator.remote_id(),
                    )));
                }
                InitiatorState::Ack => {
                    if buf.len() < 2 {
                        return Ok(None);
                    }

                    let payload_size = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                    let total_size = payload_size + 2;

                    if buf.len() < total_size {
                        return Ok(None);
                    }

                    self.initiator
                        .read_ack_message(&mut *buf.split_to(total_size))?;
                    self.state = InitiatorState::Header;
                    return Ok(Some(IngressInitiatorValue::Ack));
                }
                InitiatorState::Header => {
                    if buf.len() < Initiator::header_len() {
                        return Ok(None);
                    }

                    self.initiator
                        .assert_mac_from_header(&mut *buf.split_to(Initiator::header_len()))?;
                    self.state = InitiatorState::Body;
                }
                InitiatorState::Body => {
                    if buf.len() < self.initiator.body_len() {
                        return Ok(None);
                    }

                    let mut data = buf.split_to(self.initiator.body_len());
                    let bytes =
                        Bytes::copy_from_slice(&self.initiator.assert_mac_from_body(&mut *data)?);
                    self.state = InitiatorState::Header;
                    return Ok(Some(IngressInitiatorValue::Message(bytes)));
                }
            }
        }
    }
}

/// impl for helper objects to write out messages as bytes.
impl Encoder<EgressInitiatorValue> for Codec {
    type Error = io::Error;

    fn encode(
        &mut self,
        item: EgressInitiatorValue,
        buf: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        match item {
            EgressInitiatorValue::Auth => {
                self.state = InitiatorState::Ack;
                self.initiator.write_auth_message(buf);
                Ok(())
            }
            EgressInitiatorValue::Ack => {
                self.state = InitiatorState::Header;
                self.initiator.write_ack_message(buf);
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

impl<Io> MessageStream<Io>
where
    Io: Transport,
{
    /// `authenticate` performs Phase I of the protocol where auth and ack
    /// messages are exchanged between the initiator and recipient.
    pub async fn authenticate(
        transport: Io,
        secret_key: SecretKey,
        remote_id: RecipientId,
    ) -> Result<Self, HandshakeError> {
        let codec = Codec::new_client(secret_key, remote_id)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "codec start up failed."))?;

        let mut transport: Framed<Io, Codec> = codec.framed(transport);
        transport.send(EgressInitiatorValue::Auth).await?;

        let ack = transport.try_next().await?;

        if let Some(IngressInitiatorValue::Ack) = ack {
            Ok(Self {
                stream: transport,
                remote_id,
            })
        } else {
            Err(HandshakeError::InvalidAckData)
        }
    }

    /// Get remote id of recipient initator is connected to,
    pub fn remote_id(&self) -> RecipientId {
        self.remote_id
    }
}

/// impl for Stream trait for MessageStream
impl<Io> Stream for MessageStream<Io>
where
    Io: Transport,
{
    type Item = Result<Bytes, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match ready!(Pin::new(&mut self.get_mut().stream).poll_next(cx)) {
            Some(Ok(IngressInitiatorValue::Message(body))) => Poll::Ready(Some(Ok(body))),
            Some(other) => Poll::Ready(Some(Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "Initiator protocol error: expected message, received {:?}",
                    other
                ),
            )))),
            None => Poll::Ready(None),
        }
    }
}

/// impl for Sink trait for MessageStream
impl<Io> Sink<Bytes> for MessageStream<Io>
where
    Io: Transport,
{
    type Error = io::Error;

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).start_send(EgressInitiatorValue::Message(item))?;

        Ok(())
    }

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_ready(cx)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_close(cx)
    }
}
