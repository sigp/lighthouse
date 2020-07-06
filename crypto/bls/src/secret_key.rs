use crate::{
    public_key::{PublicKey, TPublicKey},
    signature::{Signature, TSignature},
    Error, Hash256, SecretHash,
};
use std::marker::PhantomData;

pub const SECRET_KEY_BYTES_LEN: usize = 32;

pub trait TSecretKey<SignaturePoint, PublicKeyPoint>: Sized {
    fn random() -> Self;

    fn sign(&self, msg: Hash256) -> SignaturePoint;

    fn public_key(&self) -> PublicKeyPoint;

    fn serialize(&self) -> SecretHash;

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

    pub fn serialize(&self) -> SecretHash {
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
