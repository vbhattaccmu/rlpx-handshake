//! A module for error handling for the handshake operation between the initiator and recipient.

use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("IO error")]
    IO(#[from] io::Error),
    #[error("mac check failure")]
    MacCheckFailed,
    #[error("invalid auth data")]
    InvalidAuthData,
    #[error("invalid ack data")]
    InvalidAckData,
    #[error("invalid header")]
    InvalidHeaderData,
    #[error("data deserialization failed")]
    DeserializationFailure,
    #[error("communication failed")]
    CommFailure,
    #[error("public key to peer id conversion failed")]
    P2IDFailed,
    #[error("peer id to public key conversion failed")]
    ID2PFailed,
    #[error("other")]
    Other(#[from] anyhow::Error),
}

impl From<HandshakeError> for io::Error {
    fn from(error: HandshakeError) -> Self {
        Self::new(io::ErrorKind::Other, format!("error: {:?}", error))
    }
}

impl From<rlp::DecoderError> for HandshakeError {
    fn from(error: rlp::DecoderError) -> Self {
        Self::Other(error.into())
    }
}

impl From<secp256k1::Error> for HandshakeError {
    fn from(error: secp256k1::Error) -> Self {
        Self::Other(error.into())
    }
}
