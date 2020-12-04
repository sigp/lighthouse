use crate::{
    generic_public_key::{GenericPublicKey, TPublicKey},
    generic_signature::{GenericSignature, TSignature},
    Error, Hash256, ZeroizeHash,
};
use std::marker::PhantomData;

/// The byte-length of a BLS secret key.
pub const SECRET_KEY_BYTES_LEN: usize = 32;

/// Implemented on some struct from a BLS library so it may be used as the `point` in a
/// `GenericSecretKey`.
pub trait TSecretKey<SignaturePoint, PublicKeyPoint>: Sized {
    /// Instantiate `Self` from some secure source of entropy.
    fn random() -> Self;

    /// Signs `msg`.
    fn sign(&self, msg: Hash256) -> SignaturePoint;

    /// Returns the public key that corresponds to self.
    fn public_key(&self) -> PublicKeyPoint;

    /// Serialize `self` as compressed bytes.
    fn serialize(&self) -> ZeroizeHash;

    /// Deserialize `self` from compressed bytes.
    fn deserialize(bytes: &[u8]) -> Result<Self, Error>;
}

#[derive(Clone)]
pub struct GenericSecretKey<Sig, Pub, Sec> {
    /// The underlying point which performs *actual* cryptographic operations.
    point: Sec,
    _phantom_signature: PhantomData<Sig>,
    _phantom_public_key: PhantomData<Pub>,
}

impl<Sig, Pub, Sec> GenericSecretKey<Sig, Pub, Sec>
where
    Sig: TSignature<Pub>,
    Pub: TPublicKey,
    Sec: TSecretKey<Sig, Pub>,
{
    /// Instantiate `Self` from some secure source of entropy.
    pub fn random() -> Self {
        Self {
            point: Sec::random(),
            _phantom_signature: PhantomData,
            _phantom_public_key: PhantomData,
        }
    }

    /// Signs `msg`.
    pub fn sign(&self, msg: Hash256) -> GenericSignature<Pub, Sig> {
        let is_infinity = false;
        GenericSignature::from_point(self.point.sign(msg), is_infinity)
    }

    /// Returns the public key that corresponds to self.
    pub fn public_key(&self) -> GenericPublicKey<Pub> {
        GenericPublicKey::from_point(self.point.public_key())
    }

    /// Serialize `self` as compressed bytes.
    ///
    /// ## Note
    ///
    /// The bytes that are returned are the unencrypted secret key. This is sensitive cryptographic
    /// material.
    pub fn serialize(&self) -> ZeroizeHash {
        self.point.serialize()
    }

    /// Deserialize `self` from compressed bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SECRET_KEY_BYTES_LEN {
            Err(Error::InvalidSecretKeyLength {
                got: bytes.len(),
                expected: SECRET_KEY_BYTES_LEN,
            })
        } else if bytes.iter().all(|b| *b == 0) {
            Err(Error::InvalidZeroSecretKey)
        } else {
            Ok(Self {
                point: Sec::deserialize(bytes)?,
                _phantom_signature: PhantomData,
                _phantom_public_key: PhantomData,
            })
        }
    }
}
