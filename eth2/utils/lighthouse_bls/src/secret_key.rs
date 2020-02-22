use crate::Error;
use ssz::{Decode, Encode};
use std::marker::PhantomData;
use tree_hash::TreeHash;

pub const SECRET_KEY_BYTES_LEN: usize = 48;

pub trait TSecretKey<Signature>: Sized {
    fn random() -> Self;

    fn sign(&mut self, msg: &[u8]) -> Signature;

    fn serialize(&self) -> [u8; SECRET_KEY_BYTES_LEN];

    fn deserialize(bytes: &[u8]) -> Result<Self, Error>;
}

pub struct SecretKey<Signature, T: TSecretKey<Signature>> {
    point: T,
    _phantom: PhantomData<Signature>,
}

impl<Signature, T: TSecretKey<Signature>> SecretKey<Signature, T> {
    pub fn random() -> Self {
        Self {
            point: T::random(),
            _phantom: PhantomData,
        }
    }

    pub fn sign(&mut self, msg: &[u8]) -> Signature {
        self.point.sign(msg)
    }

    pub fn serialize(&self) -> [u8; SECRET_KEY_BYTES_LEN] {
        self.point.serialize()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            point: T::deserialize(bytes)?,
            _phantom: PhantomData,
        })
    }
}

impl<Signature, T: TSecretKey<Signature>> Encode for SecretKey<Signature, T> {
    impl_ssz_encode!(SECRET_KEY_BYTES_LEN);
}

impl<Signature, T: TSecretKey<Signature>> Decode for SecretKey<Signature, T> {
    impl_ssz_decode!(SECRET_KEY_BYTES_LEN);
}

impl<Signature, T: TSecretKey<Signature>> TreeHash for SecretKey<Signature, T> {
    impl_tree_hash!(SECRET_KEY_BYTES_LEN);
}
