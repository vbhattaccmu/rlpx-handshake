//! Core initiator module which defines th following :-
//! 1. The method to call core handshake with recipient.
//! 2. Cryptographic methods required for auth-ack and protocol level connectivity with local recipient node.

use aes_ctr::{
    cipher::{NewStreamCipher, StreamCipher},
    Aes128Ctr, Aes256Ctr,
};
use byteorder::{BigEndian, ReadBytesExt};
use bytes::{BufMut, Bytes, BytesMut};
use digest::Digest;
use ethereum_types::{H128, H256};
use rand::{thread_rng, Rng};
use rlp::{Rlp, RlpStream};
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    rand::rngs::OsRng,
    PublicKey, Secp256k1, SecretKey,
};
use sha3::Keccak256;
use std::convert::TryFrom;
use tokio::net::TcpStream;

use crate::{
    error::HandshakeError,
    server::networking::*,
    types::*,
    utilities::{ecdh_xchng, kdf},
    utilities::{id2pubkey, pubkey2id, sha256, sha256_hmac},
};

/// Initiator struct represents the paricipant initiating the cryptographic protocol.
#[derive(Debug)]
pub struct Initiator {
    /// A `H256` value representing a nonce used for cryptographic operations.
    nonce: H256,
    /// A `PublicKey` representing the public key of the initiator.
    initiator_public_key: PublicKey,
    /// A `SecretKey` representing the secret key of the initiator.
    initiator_secret_key: SecretKey,
    /// An optional `Bytes` value containing the initial message.
    initial_msg: Option<Bytes>,
    /// An optional `usize` value indicating the size of the message body.
    body_size: Option<usize>,
    /// An optional `MAC` value for egress message authentication code.
    egress_mac: Option<MAC>,
    /// An optional `MAC` value for ingress message authentication code.
    ingress_mac: Option<MAC>,
    /// An optional `Aes256Ctr` value for ingress AES-256 encryption.
    ingress_aes: Option<Aes256Ctr>,
    /// An optional `Aes256Ctr` value for egress AES-256 encryption.
    egress_aes: Option<Aes256Ctr>,
    /// An optional `H256` value representing a recipient's nonce.
    recipient_nonce: Option<H256>,
    /// An optional `Bytes` value containing the recipient's initial message.
    remote_initial_msg: Option<Bytes>,
    /// A `SecretKey` representing the ephemeral secret key.
    ephemeral_secret_key: SecretKey,
    /// A `PublicKey` representing the ephemeral public key.
    ephemeral_public_key: PublicKey,
    /// An optional `PublicKey` representing the remote party's public key.
    remote_public_key: Option<PublicKey>,
    /// An optional `RecipientId` representing the remote recipient's identifier.
    pub remote_id: Option<RecipientId>,
    /// An optional `H256` value representing an ephemeral shared secret.
    ephemeral_shared_secret: Option<H256>,
    /// An optional `PublicKey` representing the remote ephemeral public key.
    remote_ephemeral_public_key: Option<PublicKey>,
}

impl Initiator {
    /// Get the remote id of the connected recipient.
    pub fn remote_id(&self) -> RecipientId {
        self.remote_id.unwrap()
    }

    /// Utility to perform handshake with recipient.
    pub async fn perform_handshake_with_recipient(
        recipient_endpoint: &str,
        remote_id: RecipientId,
    ) -> Result<OutboundMessage, HandshakeError> {
        // Generate initiator creds
        let (secret_key, _) = Secp256k1::new().generate_keypair(&mut OsRng);
        // Initiate tcp stream
        let transport = TcpStream::connect(recipient_endpoint)
            .await
            .map_err(|_| HandshakeError::CommFailure)?;

        // Phase - I Send auth and receive ack to/from recipient
        let message_stream = MessageStream::authenticate(transport, secret_key, remote_id)
            .await
            .map_err(|e| e)?;

        // Phase - II Send/Recv outbound message to/from recipient
        let message_from_recipient = Peer::communicate(
            message_stream,
            secret_key,
            ProtocolVersion::V5,
            "0".to_string(),
            30303,
        )
        .await
        .map_err(|e| e)?;

        Ok(message_from_recipient)
    }

    /// Utility to spin upa new initiator client.
    pub fn new_client(
        secret_key: SecretKey,
        remote_id: RecipientId,
    ) -> Result<Self, HandshakeError> {
        let nonce = H256::random();
        let ephemeral_secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
        let remote_public_key = id2pubkey(remote_id)?;
        let public_key = PublicKey::from_secret_key(&Secp256k1::new(), &secret_key);
        let ephemeral_public_key =
            PublicKey::from_secret_key(&Secp256k1::new(), &ephemeral_secret_key);

        Ok(Self {
            initiator_secret_key: secret_key,
            initiator_public_key: public_key,
            ephemeral_secret_key,
            ephemeral_public_key,
            nonce,
            remote_id: Some(remote_id),
            remote_public_key: Some(remote_public_key),
            remote_ephemeral_public_key: None,
            recipient_nonce: None,
            ephemeral_shared_secret: None,
            initial_msg: None,
            remote_initial_msg: None,
            egress_aes: None,
            ingress_aes: None,
            egress_mac: None,
            ingress_mac: None,
            body_size: None,
        })
    }

    /// Create encrypted auth message.
    /// Formulations taken from source [RLPx protocol]: https://hackmd.io/@Nhlanhla/SJv3wnhMK
    pub fn write_auth_message(&mut self, buffer: &mut BytesMut) {
        // Create unencrypted authentication message
        let unencrypted = self.create_auth_unencrypted();

        // Initialize empty buffer
        let mut buf = buffer.split_off(buffer.len());
        // reserve index for length of the buffer
        buf.put_u16(0);

        // Initialize empty 'encrypted' buffer
        let mut encrypted = buf.split_off(buf.len());
        // Encrypt the 'unencrypted' message and store it in the 'encrypted' buffer
        self.encrypt_initiator_message(&unencrypted, &mut encrypted);
        // Convert the length of the 'encrypted' message to a u16 and store it in 'len_bytes'
        let len_bytes = u16::try_from(encrypted.len()).unwrap().to_be_bytes();
        // Copy the length bytes to the beginning of buf
        buf[..len_bytes.len()].copy_from_slice(&len_bytes);
        // Concatenate the 'encrypted' buffer to the end of buf
        buf.unsplit(encrypted);

        // Set the 'init_msg' field of 'self' to a Bytes copy of buf
        self.initial_msg = Some(Bytes::copy_from_slice(&buf));

        // Concatenate buf to the end of the original 'buffer'
        buffer.unsplit(buf);
    }

    /// Utility to create unencrypted auth message.
    /// auth = auth-size || enc-auth-body
    /// auth-size = size of enc-auth-body, encoded as a big-endian 16-bit integer
    /// auth-body = [sig, initiator-pubk, initiator-nonce, auth-vsn, ...]
    /// Formulations taken from source [RLPx protocol]: https://hackmd.io/@Nhlanhla/SJv3wnhMK
    pub fn create_auth_unencrypted(&self) -> BytesMut {
        let shared_secret =
            ecdh_xchng(&self.remote_public_key.unwrap(), &self.initiator_secret_key);
        let msg = shared_secret ^ self.nonce;
        let (rec_id, sig) = Secp256k1::new()
            .sign_ecdsa_recoverable(
                &secp256k1::Message::from_slice(msg.as_bytes()).unwrap(),
                &self.ephemeral_secret_key,
            )
            .serialize_compact();

        // signature
        let mut signature_bytes = [0_u8; 65];
        signature_bytes[..64].copy_from_slice(&sig);
        signature_bytes[64] = rec_id.to_i32() as u8;

        // auth-body = [sig, initiator-pubk, initiator-nonce, auth-vsn, ...]
        let mut auth_body = RlpStream::new_list(4);
        auth_body.append(&(&signature_bytes as &[u8]));
        auth_body.append(&pubkey2id(&self.initiator_public_key));
        auth_body.append(&self.nonce);
        auth_body.append(&PROTOCOL_VERSION);

        let mut auth_body = auth_body.out();
        auth_body.resize(auth_body.len() + thread_rng().gen_range(100..=300), 0);

        auth_body
    }

    /// Utility to decrypt and parse auth message.
    pub fn commit_auth(&mut self, data: &mut [u8]) -> Result<(), HandshakeError> {
        self.remote_initial_msg = Some(Bytes::copy_from_slice(data));
        let unencrypted = self.decrypt_recipient_message(data)?;
        self.parse_auth_unencrypted(&unencrypted)
    }

    /// Utility to parse auth message following protocol.
    fn parse_auth_unencrypted(&mut self, data: &[u8]) -> Result<(), HandshakeError> {
        let rlp = Rlp::new(data);
        let mut rlp = rlp.into_iter();

        // Compute signature
        let signature_data = rlp
            .next()
            .ok_or(rlp::DecoderError::RlpInvalidLength)?
            .data()?;
        if signature_data.len() != 65 {
            return Err(HandshakeError::InvalidAuthData);
        }
        let signature = RecoverableSignature::from_compact(
            &signature_data[0..64],
            RecoveryId::from_i32(signature_data[64] as i32)?,
        )?;

        // Compute remote id, nonce and public key
        let remote_id = rlp
            .next()
            .ok_or(rlp::DecoderError::RlpInvalidLength)?
            .as_val()?;
        self.remote_id = Some(remote_id);
        self.remote_public_key =
            Some(id2pubkey(remote_id).map_err(|_| HandshakeError::ID2PFailed)?);
        self.recipient_nonce = Some(
            rlp.next()
                .ok_or(rlp::DecoderError::RlpInvalidLength)?
                .as_val()?,
        );

        // Compute ephemeral_shared_secret
        let shared_secret: H256 =
            ecdh_xchng(&self.remote_public_key.unwrap(), &self.initiator_secret_key);
        self.remote_ephemeral_public_key = Some(
            Secp256k1::new().recover_ecdsa(
                &secp256k1::Message::from_slice(
                    (shared_secret ^ self.recipient_nonce.unwrap()).as_ref(),
                )
                .unwrap(),
                &signature,
            )?,
        );
        self.ephemeral_shared_secret = Some(ecdh_xchng(
            &self.remote_ephemeral_public_key.unwrap(),
            &self.ephemeral_secret_key,
        ));

        Ok(())
    }

    /// Utility to read ack from a buffer and setup a frame
    pub fn read_ack_message(&mut self, data: &mut [u8]) -> Result<(), HandshakeError> {
        self.remote_initial_msg = Some(Bytes::copy_from_slice(data));
        let unencrypted = self.decrypt_recipient_message(data)?;

        self.parse_unencrypted_ack(&unencrypted)?;
        self.setup_message_frame(false);

        Ok(())
    }

    /// Utility to seriaize ack to a buffer and setup a frame
    pub fn write_ack_message(&mut self, buffer: &mut BytesMut) {
        let unencrypted = self.create_unencrypted_ack();

        // Initialize empty buffer
        let mut buf: BytesMut = buffer.split_off(buffer.len());
        // reserve index for length of the buffer
        buf.put_u16(0);

        let mut encrypted = buf.split_off(buf.len());
        self.encrypt_initiator_message(&unencrypted, &mut encrypted);
        let len_bytes = u16::try_from(encrypted.len()).unwrap().to_be_bytes();
        buf.unsplit(encrypted);
        buf[..len_bytes.len()].copy_from_slice(&len_bytes[..]);

        self.initial_msg = Some(buf.clone().freeze());
        buffer.unsplit(buf);

        self.setup_message_frame(true);
    }

    /// Utility to create unencrypted ack message.
    /// ack = ack-size || enc-ack-body
    /// ack-size = size of enc-ack-body, encoded as a big-endian 16-bit integer
    /// ack-body = [recipient-ephemeral-pubk, recipient-nonce, ack-vsn, ...]
    /// Formulations taken from source [RLPx protocol]: https://hackmd.io/@Nhlanhla/SJv3wnhMK
    fn create_unencrypted_ack(&self) -> BytesMut {
        let mut ack = RlpStream::new_list(3);

        ack.append(&pubkey2id(&self.ephemeral_public_key));
        ack.append(&self.nonce);
        ack.append(&PROTOCOL_VERSION);

        ack.out()
    }

    /// Utility to parse ack message following protocol.
    fn parse_unencrypted_ack(&mut self, data: &[u8]) -> Result<(), HandshakeError> {
        let rlp = Rlp::new(data);
        let mut rlp = rlp.into_iter();

        // set remote_ephemeral_public_key
        self.remote_ephemeral_public_key = Some(id2pubkey(
            rlp.next()
                .ok_or(rlp::DecoderError::RlpInvalidLength)?
                .as_val()?,
        )?);

        // set recipient_nonce
        self.recipient_nonce = Some(
            rlp.next()
                .ok_or(rlp::DecoderError::RlpInvalidLength)?
                .as_val()?,
        );

        // set ephemeral_shared_secret
        self.ephemeral_shared_secret = Some(ecdh_xchng(
            &self.remote_ephemeral_public_key.unwrap(),
            &self.ephemeral_secret_key,
        ));

        Ok(())
    }

    /// Utility to encrypt the message being sent to recipient.
    fn encrypt_initiator_message(&self, data: &[u8], buffer: &mut BytesMut) {
        // Reserve enough capacity in buffer to accommodate the encrypted message
        buffer.reserve(secp256k1::constants::UNCOMPRESSED_PUBLIC_KEY_SIZE + 16 + data.len() + 32);
        // Generate a new secret key
        let secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
        // Append the uncompressed public key derived from the secret key to buffer
        buffer.extend_from_slice(
            &PublicKey::from_secret_key(&Secp256k1::new(), &secret_key).serialize_uncompressed(),
        );
        // Perform an elliptic curve Diffie-Hellman key exchange to derive 'x'
        let secret: H256 = ecdh_xchng(&self.remote_public_key.unwrap(), &secret_key);

        // Initialize a 32-byte key with zeros
        let mut key = [0_u8; 32];
        // Perform key derivation function on 'x' and store the result in 'key'
        kdf(secret, &[], &mut key);
        // Split 'key' into encryption key and MAC key
        let enc_key = H128::from_slice(&key[0..16]);
        let mac_key = sha256(&key[16..32]);

        // Generate a random initialization vector (IV)
        let initialization_vector = H128::random();
        // Create an AES-128 CTR encryptor with the encryption key and IV
        let mut encryptor = Aes128Ctr::new(
            enc_key.as_ref().into(),
            initialization_vector.as_ref().into(),
        );
        // Encrypt the 'data' using the encryptor and store the result in 'encrypted'
        let mut encrypted = data.to_vec();
        encryptor.encrypt(&mut encrypted);

        // Calculate the total size of the encrypted message
        let total_size: u16 = u16::try_from(65 + 16 + data.len() + 32).unwrap();
        // Generate a tag (MAC) using HMAC-SHA256
        let tag = sha256_hmac(
            mac_key.as_ref(),
            &[initialization_vector.as_bytes(), &encrypted],
            &total_size.to_be_bytes(),
        );

        // Append the iv, encrypted data, and tag to the buffer
        buffer.extend_from_slice(initialization_vector.as_bytes());
        buffer.extend_from_slice(&encrypted);
        buffer.extend_from_slice(tag.as_ref());
    }

    /// Utility to decrypt the message received from recipient.
    fn decrypt_recipient_message<'a>(
        &self,
        data: &'a mut [u8],
    ) -> Result<&'a mut [u8], HandshakeError> {
        // Split the data into 'auth_data' and 'encrypted' parts
        let (auth_data, encrypted) = data.split_at_mut(2);
        // Split 'encrypted' into 'pubkey_bytes' and 'encrypted' parts
        let (pubkey_bytes, encrypted) = encrypted.split_at_mut(65);

        // Parse 'pubkey_bytes' into a public key
        let public_key =
            PublicKey::from_slice(&pubkey_bytes).map_err(|_| HandshakeError::ID2PFailed)?;
        // Split 'encrypted' into 'data_vector' and 'tag_bytes' parts
        let (data_vector, tag_bytes) = encrypted.split_at_mut(encrypted.len() - 32);
        // Split 'data_vector' into 'initialization_vector' and 'encrypted_data' parts
        let (initialization_vector, encrypted_data) = data_vector.split_at_mut(16);

        // Initialize 'key' with zeroes
        let mut key = [0_u8; 32];
        // Convert 'tag_bytes' into a tag
        let tag = H256::from_slice(tag_bytes);
        // Perform ECDH key exchange to get 'x'
        let secret = ecdh_xchng(&public_key, &self.initiator_secret_key);

        // Apply key derivation function (kdf) to derive the encryption key 'enc_key' and the MAC key 'mac_key'
        kdf(secret, &[], &mut key);
        let enc_key = H128::from_slice(&key[0..16]);
        let mac_key = sha256(&key[16..32]);

        // Compute the tag for verification
        let check_tag = sha256_hmac(
            mac_key.as_ref(),
            &[initialization_vector, encrypted_data],
            auth_data,
        );
        // Compare the computed tag with the received tag
        if check_tag != tag {
            return Err(HandshakeError::MacCheckFailed);
        }

        // Initialize 'decrypted_data' with 'encrypted_data'
        let mut decrypted_data = encrypted_data;
        // Create a decryptor with 'enc_key' and 'initialization_vector'
        let mut decryptor =
            Aes128Ctr::new(enc_key.as_ref().into(), (&*initialization_vector).into());
        // Decrypt 'decrypted_data' using the decryptor
        decryptor.decrypt(&mut decrypted_data);

        // Return the decrypted data
        Ok(decrypted_data)
    }

    /// Setup the frame for communication.
    /// Formulations taken from source [RLPx protocol]: https://hackmd.io/@Nhlanhla/SJv3wnhMK
    pub fn setup_message_frame(&mut self, is_incoming: bool) {
        // Calculate h_nonce based on the is_incoming flag
        let h_nonce: H256 = if is_incoming {
            // For writing ack to a buffer
            let mut hasher = Keccak256::new();
            hasher.update(self.nonce.as_ref());
            hasher.update(self.recipient_nonce.unwrap().as_ref());
            H256::from(hasher.finalize().as_ref())
        } else {
            // For reading ack from a buffer
            let mut hasher = Keccak256::new();
            hasher.update(self.recipient_nonce.unwrap().as_ref());
            hasher.update(self.nonce.as_ref());
            H256::from(hasher.finalize().as_ref())
        };

        let initialization_vector = H128::default();

        // Calculate shared_secret
        // shared-secret = keccak256(ephemeral-key || keccak256(nonce || initiator-nonce))
        let shared_secret: H256 = {
            let mut hasher = Keccak256::new();
            hasher.update(self.ephemeral_shared_secret.unwrap().as_ref());
            hasher.update(h_nonce.as_ref());
            H256::from(hasher.finalize().as_ref())
        };

        // Calculate aes_secret
        // aes-secret = keccak256(ephemeral-key || shared-secret)
        let aes_secret: H256 = {
            let mut hasher = Keccak256::new();
            hasher.update(self.ephemeral_shared_secret.unwrap().as_ref());
            hasher.update(shared_secret.as_ref());
            H256::from(hasher.finalize().as_ref())
        };

        // Set ingress_aes using aes_secret and initialization_vector
        self.ingress_aes = Some(Aes256Ctr::new(
            aes_secret.as_ref().into(),
            initialization_vector.as_ref().into(),
        ));

        // Set egress_aes using aes_secret and initialization_vector
        self.egress_aes = Some(Aes256Ctr::new(
            aes_secret.as_ref().into(),
            initialization_vector.as_ref().into(),
        ));

        // Calculate mac_secret
        // mac-secret = keccak256(ephemeral-key || aes-secret)
        let mac_secret: H256 = {
            let mut hasher = Keccak256::new();
            hasher.update(self.ephemeral_shared_secret.unwrap().as_ref());
            hasher.update(aes_secret.as_ref());
            H256::from(hasher.finalize().as_ref())
        };

        // Set ingress_mac and update it
        // ingress-mac = keccak256.init((mac-secret ^ initiator-nonce) || ack)
        self.ingress_mac = Some(MAC::new(mac_secret));
        self.ingress_mac
            .as_mut()
            .unwrap()
            .update((mac_secret ^ self.nonce).as_ref());
        self.ingress_mac
            .as_mut()
            .unwrap()
            .update(self.remote_initial_msg.as_ref().unwrap());

        // Set egress_mac and update it
        // egress-mac = keccak256.init((mac-secret ^ recipient-nonce) || auth)
        self.egress_mac = Some(MAC::new(mac_secret));
        self.egress_mac
            .as_mut()
            .unwrap()
            .update((mac_secret ^ self.recipient_nonce.unwrap()).as_ref());
        self.egress_mac
            .as_mut()
            .unwrap()
            .update(self.initial_msg.as_ref().unwrap());
    }

    /// Utility to assert mac from header.
    /// Note: cryptographic handshake is complete if MAC of first encrypted frame is valid on both sides
    /// Source [RLPx protocol]: https://hackmd.io/@Nhlanhla/SJv3wnhMK
    pub fn assert_mac_from_header(&mut self, data: &mut [u8]) -> Result<usize, HandshakeError> {
        // Split 'data' into 'header_data_bytes' and 'mac_bytes' parts
        let (header_data_bytes, mac_bytes) = data.split_at_mut(16);
        // Create a mutable reference to 'header_data_bytes' as 'header'
        let mut header = HeaderDataBytes::from_mut_slice(header_data_bytes);
        // Convert 'mac_bytes' into a MAC
        let mac = H128::from_slice(&mac_bytes[..16]);
        // Update the ingress MAC with 'header'
        self.ingress_mac.as_mut().unwrap().update_header(&header);

        // Compute the MAC digest
        let check_mac = self.ingress_mac.as_mut().unwrap().digest();
        // Compare the computed MAC with the received MAC
        if check_mac != mac {
            return Err(HandshakeError::MacCheckFailed);
        }

        // Decrypt 'header' using the ingress AES decryptor
        self.ingress_aes.as_mut().unwrap().decrypt(&mut header);
        // Read the body size from 'header' and convert it to usize
        self.body_size = Some(
            usize::try_from(header.as_slice().read_uint::<BigEndian>(3)?)
                .map_err(|_| HandshakeError::DeserializationFailure)?,
        );

        // Return the body size
        Ok(self.body_size.unwrap())
    }

    /// Utility to check if MAC digest matches with MAC retrieved from body.
    /// Note: cryptographic handshake is complete if MAC of first encrypted frame is valid on both sides
    /// Source [RLPx protocol]: https://hackmd.io/@Nhlanhla/SJv3wnhMK
    pub fn assert_mac_from_body<'a>(
        &mut self,
        data: &'a mut [u8],
    ) -> Result<&'a mut [u8], HandshakeError> {
        // Split 'data' into 'body' and 'mac_bytes' parts
        let (body, mac_bytes) = data.split_at_mut(data.len() - 16);
        // Convert 'mac_bytes' into a MAC
        let mac = H128::from_slice(mac_bytes);
        // Update the ingress MAC with 'body'
        self.ingress_mac.as_mut().unwrap().update_body(body);
        // Compute the MAC digest
        let check_mac = self.ingress_mac.as_mut().unwrap().digest();

        // Compare the computed MAC with the received MAC
        if check_mac != mac {
            return Err(HandshakeError::MacCheckFailed);
        }

        // Get the body size from the previous 'read_header' call
        let size = self.body_size.unwrap();
        // Reset the body size to None
        self.body_size = None;
        // Create a mutable reference to 'body' as 'ret'
        let mut ret = body;
        // Decrypt 'ret' using the ingress AES decryptor
        self.ingress_aes.as_mut().unwrap().decrypt(&mut ret);

        // Split 'ret' at 'size' and return the first part
        Ok(ret.split_at_mut(size).0)
    }

    /// Return header length
    pub const fn header_len() -> usize {
        32
    }

    /// Return body length
    pub fn body_len(&self) -> usize {
        let len = self.body_size.unwrap();
        (if len % 16 == 0 {
            len
        } else {
            (len / 16 + 1) * 16
        }) + 16
    }
}

/// Current protocol version
const PROTOCOL_VERSION: usize = 5;
