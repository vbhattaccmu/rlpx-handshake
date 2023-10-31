use hex_literal::hex;

mod error;
mod server;
mod types;
mod utilities;

pub use crate::server::initiator::*;
pub use crate::types::RecipientId;

/// remote id of geth node
pub const REMOTE_ID: RecipientId = RecipientId(hex!("af22c29c316ad069cf48a09a4ad5cf04a251b411e45098888d114c6dd7f489a13786620d5953738762afa13711d4ffb3b19aa5de772d8af72f851f7e9c5b164a"));

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::initiator::Initiator;
    use crate::REMOTE_ID;

    #[tokio::test]
    async fn test_handshake_success() {
        let recipient_node_endpoint = "127.0.0.1:30303";
        let response =
            Initiator::perform_handshake_with_recipient(recipient_node_endpoint, REMOTE_ID).await;
        assert!(response.is_ok());
        let received_message = response.unwrap();
        // the easiest way to know if the handshake as successful is as folows:-
        // 1. recipient sends its client version "Geth/v1.10.1-stable-c2d2f4ed/linux-amd64/go1.16"
        // 2. recipient sends its protocol version 5
        // 3. recipient sends its remote ID
        assert_eq!(
            received_message.client_version,
            "Geth/v1.10.1-stable-c2d2f4ed/linux-amd64/go1.16"
        );
        assert_eq!(received_message.protocol_version, 5);
        assert_eq!(received_message.id, REMOTE_ID);
    }

    #[tokio::test]
    async fn test_handshake_failure_with_incorrect_id() {
        let recipient_node_endpoint = "127.0.0.1:30303";
        // use an incorrect remote id
        let remote_id: RecipientId = RecipientId(hex!("ab22c29c316ad069cf48a09a4ad5cf04a251b411e45098888d114c6dd7f489a13786620d5953738762afa13711d4ffb3b19aa5de772d8af72f851f7e9c5b164a"));
        let response =
            Initiator::perform_handshake_with_recipient(recipient_node_endpoint, remote_id).await;
        assert!(response.is_err());
        // expect IO error
        assert_eq!(response.unwrap_err().to_string(), "IO error".to_string());
    }
}
