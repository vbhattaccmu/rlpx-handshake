//! This module provides a `MAC` (Message Authentication Code) implementation for securing data using
//! AES encryption and Keccak256 hashing.

use aes::*;
use block_modes::{block_padding::NoPadding, BlockMode, Ecb};
use ethereum_types::{H128, H256};
use generic_array::{typenum::U16, GenericArray};
use sha3::{Digest, Keccak256};

pub type HeaderDataBytes = GenericArray<u8, U16>;

#[derive(Debug)]
pub struct MAC {
    secret: H256,
    hasher: Keccak256,
}

impl MAC {
    /// Creates a new `MAC` instance with the given secret key.
    pub fn new(secret: H256) -> Self {
        Self {
            secret,
            hasher: Keccak256::new(),
        }
    }

    /// Updates the `MAC` instance with the provided data.
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data)
    }

    /// Updates the `MAC` instance using header data for integrity checking.
    pub fn update_header(&mut self, data: &HeaderDataBytes) {
        let aes = Ecb::<_, NoPadding>::new(
            Aes256::new_varkey(self.secret.as_ref()).unwrap(),
            &Default::default(),
        );

        let mut encrypted = self.digest().to_fixed_bytes();
        aes.encrypt(&mut encrypted, H128::len_bytes()).unwrap();
        for i in 0..data.len() {
            encrypted[i] ^= data[i];
        }

        self.hasher.update(encrypted);
    }

    /// Updates the `MAC` instance using body data for integrity checking.
    pub fn update_body(&mut self, data: &[u8]) {
        self.hasher.update(data);
        let prev = self.digest();
        let aes = Ecb::<_, NoPadding>::new(
            Aes256::new_varkey(self.secret.as_ref()).unwrap(),
            &Default::default(),
        );

        let mut encrypted = self.digest().to_fixed_bytes();
        aes.encrypt(&mut encrypted, H128::len_bytes()).unwrap();
        for i in 0..16 {
            encrypted[i] ^= prev[i];
        }

        self.hasher.update(encrypted);
    }

    /// Computes the digest of the `MAC` instance.
    pub fn digest(&self) -> H128 {
        H128::from_slice(&self.hasher.clone().finalize()[0..16])
    }
}
