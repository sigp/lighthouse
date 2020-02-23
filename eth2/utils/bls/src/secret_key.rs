use crate::Error;
use ssz::{Decode, Encode};
use std::marker::PhantomData;
use tree_hash::TreeHash;

pub const SECRET_KEY_BYTES_LEN: usize = 48;

pub trait TSecretKey<Signature, PublicKey>: Sized {
    fn random() -> Self;

    fn sign(&mut self, msg: &[u8]) -> Signature;

    fn public_key(&self) -> PublicKey;

    fn serialize(&self) -> [u8; SECRET_KEY_BYTES_LEN];

    fn deserialize(bytes: &[u8]) -> Result<Self, Error>;
}

#[derive(Clone)]
pub struct SecretKey<Signature, PublicKey, T: TSecretKey<Signature, PublicKey>> {
    point: T,
    _phantom_signature: PhantomData<Signature>,
    _phantom_public_key: PhantomData<PublicKey>,
}

impl<Signature, PublicKey, T: TSecretKey<Signature, PublicKey>> SecretKey<Signature, PublicKey, T> {
    pub fn random() -> Self {
        Self {
            point: T::random(),
            _phantom_signature: PhantomData,
            _phantom_public_key: PhantomData,
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.point.public_key()
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
            _phantom_signature: PhantomData,
            _phantom_public_key: PhantomData,
        })
    }
}

impl<Signature, PublicKey, T: TSecretKey<Signature, PublicKey>> Encode
    for SecretKey<Signature, PublicKey, T>
{
    impl_ssz_encode!(SECRET_KEY_BYTES_LEN);
}

impl<Signature, PublicKey, T: TSecretKey<Signature, PublicKey>> Decode
    for SecretKey<Signature, PublicKey, T>
{
    impl_ssz_decode!(SECRET_KEY_BYTES_LEN);
}

impl<Signature, PublicKey, T: TSecretKey<Signature, PublicKey>> TreeHash
    for SecretKey<Signature, PublicKey, T>
{
    impl_tree_hash!(SECRET_KEY_BYTES_LEN);
}
