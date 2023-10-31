//! A generic utilities module for performing cryptographic operations like computing hashes, generating
//! recipient id from public keys and vice versa.

use ethereum_types::H256;
use hmac::{Hmac, Mac, NewMac};
use secp256k1::{PublicKey, SecretKey};
use sha2::Sha256;
use sha3::Digest;

use crate::types::*;

/// Computes the SHA256 hash for the given input using the provided data.
pub fn sha256(data: &[u8]) -> H256 {
    H256::from(Sha256::digest(data).as_ref())
}

/// Computes the HMAC-SHA256 hash for the given input and key, using the provided authentication data.
pub fn sha256_hmac(key: &[u8], input: &[&[u8]], auth_data: &[u8]) -> H256 {
    let mut hmac = Hmac::<Sha256>::new_varkey(key).unwrap();
    for input in input {
        hmac.update(input);
    }
    hmac.update(auth_data);
    H256::from_slice(&*hmac.finalize().into_bytes())
}

/// Computes recipient id from public key.
pub fn pubkey2id(pk: &PublicKey) -> RecipientId {
    RecipientId::from_slice(&pk.serialize_uncompressed()[1..])
}

/// Computes public key from recipient id.
pub fn id2pubkey(id: RecipientId) -> Result<PublicKey, secp256k1::Error> {
    let mut s = [0_u8; 65];
    s[0] = 4;
    s[1..].copy_from_slice(&id.as_bytes());
    PublicKey::from_slice(&s)
}

/// Computes the shared secret using the Elliptic Curve Diffie-Hellman (ECDH) key exchange with secp256k1 curve.
pub fn ecdh_xchng(public_key: &PublicKey, secret_key: &SecretKey) -> H256 {
    H256::from_slice(&secp256k1::ecdh::shared_secret_point(&public_key, &secret_key)[0..32])
}

/// Key Derivation Function (KDF) based on the SHA-256 hash algorithm.
pub fn kdf(secret: H256, data: &[u8], dest: &mut [u8]) {
    let mut counter = 1_u32;
    let mut offset = 0_usize;
    while offset < dest.len() {
        let mut hasher = Sha256::default();
        let buf = [
            (counter >> 24) as u8,
            (counter >> 16) as u8,
            (counter >> 8) as u8,
            counter as u8,
        ];
        hasher.update(&buf);
        hasher.update(secret.as_bytes());
        hasher.update(data);
        dest[offset..(offset + 32)].copy_from_slice(&hasher.finalize());
        offset += 32;
        counter += 1;
    }
}
