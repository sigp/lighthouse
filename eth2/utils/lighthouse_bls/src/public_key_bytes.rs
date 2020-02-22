use crate::{public_key::TPublicKey, Error, PUBLIC_KEY_BYTES_LEN};
use ssz::{Decode, Encode};
use std::marker::PhantomData;
use tree_hash::TreeHash;

pub struct PublicKeyBytes<T> {
    bytes: [u8; PUBLIC_KEY_BYTES_LEN],
    _phantom: PhantomData<T>,
}

impl<T: TPublicKey> PublicKeyBytes<T> {
    pub fn decompress(&self) -> Result<T, Error> {
        T::deserialize(&self.bytes)
    }

    pub fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        self.bytes.clone()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() == PUBLIC_KEY_BYTES_LEN {
            let mut pk_bytes = [0; PUBLIC_KEY_BYTES_LEN];
            pk_bytes[..].copy_from_slice(bytes);
            Ok(Self {
                bytes: pk_bytes,
                _phantom: PhantomData,
            })
        } else {
            Err(Error::InvalidByteLength {
                got: bytes.len(),
                expected: PUBLIC_KEY_BYTES_LEN,
            })
        }
    }
}

impl<T: TPublicKey> Encode for PublicKeyBytes<T> {
    impl_ssz_encode!(PUBLIC_KEY_BYTES_LEN);
}

impl<T: TPublicKey> Decode for PublicKeyBytes<T> {
    impl_ssz_decode!(PUBLIC_KEY_BYTES_LEN);
}

impl<T: TPublicKey> TreeHash for PublicKeyBytes<T> {
    impl_tree_hash!(PUBLIC_KEY_BYTES_LEN);
}
