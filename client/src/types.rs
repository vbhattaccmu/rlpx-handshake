//! A types module for aliasing data structures involved in communicating with the
//! local ethereum node.

use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

pub use ethereum_types::H512 as RecipientId;

/// Geth protocol version.
#[derive(Copy, Clone, Debug)]
pub enum ProtocolVersion {
    V5 = 5,
}

/// Outbound message struct
#[derive(Clone, Debug)]
pub struct OutboundMessage {
    // current protocol version
    pub protocol_version: usize,
    // current initiator version
    pub client_version: String,
    // listening port
    pub port: u16,
    // remote id recipient ID
    pub id: RecipientId,
}

impl Encodable for OutboundMessage {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.begin_list(5);
        stream.append(&self.protocol_version);
        stream.append(&self.client_version);
        stream.append(&self.port);
        stream.append(&self.id);
    }
}

impl Decodable for OutboundMessage {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self {
            protocol_version: rlp.val_at(0)?,
            client_version: rlp.val_at(1)?,
            port: rlp.val_at(3)?,
            id: rlp.val_at(4)?,
        })
    }
}
