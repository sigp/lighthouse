use crate::{
    public_key::{PublicKey, TPublicKey},
    signature::{Signature, TSignature},
    Error, Hash256,
};
use ssz::{Decode, Encode};
use std::marker::PhantomData;
use tree_hash::TreeHash;

pub const SECRET_KEY_BYTES_LEN: usize = 32;

pub trait TSecretKey<SignaturePoint, PublicKeyPoint>: Sized {
    fn random() -> Self;

    fn sign(&self, msg: Hash256) -> SignaturePoint;

    fn public_key(&self) -> PublicKeyPoint;

    fn serialize(&self) -> [u8; SECRET_KEY_BYTES_LEN];

    fn deserialize(bytes: &[u8]) -> Result<Self, Error>;
}

// TODO: remove partial eq for security reasons.
// TODO: clear memory on drop.
// Make it harder to encode.
#[derive(Clone, PartialEq)]
pub struct SecretKey<Sig, Pub, Sec> {
    point: Sec,
    _phantom_signature: PhantomData<Sig>,
    _phantom_public_key: PhantomData<Pub>,
}

impl<Sig, Pub, Sec> SecretKey<Sig, Pub, Sec>
where
    Sig: TSignature<Pub>,
    Pub: TPublicKey,
    Sec: TSecretKey<Sig, Pub>,
{
    pub fn random() -> Self {
        Self {
            point: Sec::random(),
            _phantom_signature: PhantomData,
            _phantom_public_key: PhantomData,
        }
    }

    pub fn public_key(&self) -> PublicKey<Pub> {
        PublicKey::from_point(self.point.public_key())
    }

    pub fn sign(&self, msg: Hash256) -> Signature<Pub, Sig> {
        Signature::from_point(self.point.sign(msg))
    }

    pub fn serialize(&self) -> [u8; SECRET_KEY_BYTES_LEN] {
        self.point.serialize()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            point: Sec::deserialize(bytes)?,
            _phantom_signature: PhantomData,
            _phantom_public_key: PhantomData,
        })
    }
}

impl<Sig, Pub, Sec> Encode for SecretKey<Sig, Pub, Sec>
where
    Sig: TSignature<Pub>,
    Pub: TPublicKey,
    Sec: TSecretKey<Sig, Pub>,
{
    impl_ssz_encode!(SECRET_KEY_BYTES_LEN);
}

impl<Sig, Pub, Sec> Decode for SecretKey<Sig, Pub, Sec>
where
    Sig: TSignature<Pub>,
    Pub: TPublicKey,
    Sec: TSecretKey<Sig, Pub>,
{
    impl_ssz_decode!(SECRET_KEY_BYTES_LEN);
}

impl<Sig, Pub, Sec> TreeHash for SecretKey<Sig, Pub, Sec>
where
    Sig: TSignature<Pub>,
    Pub: TPublicKey,
    Sec: TSecretKey<Sig, Pub>,
{
    impl_tree_hash!(SECRET_KEY_BYTES_LEN);
}
