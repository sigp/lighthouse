use crate::{
    generic_aggregate_public_key::TAggregatePublicKey,
    generic_aggregate_signature::TAggregateSignature,
    generic_public_key::{GenericPublicKey, TPublicKey, PUBLIC_KEY_BYTES_LEN},
    generic_secret_key::{TSecretKey, SECRET_KEY_BYTES_LEN},
    generic_signature::{TSignature, SIGNATURE_BYTES_LEN},
    Error, Hash256, ZeroizeHash, INFINITY_PUBLIC_KEY, INFINITY_SIGNATURE,
};

/// Provides the externally-facing, core BLS types.
pub mod types {
    pub use super::verify_signature_sets;
    pub use super::AggregatePublicKey;
    pub use super::AggregateSignature;
    pub use super::PublicKey;
    pub use super::SecretKey;
    pub use super::Signature;
    pub use super::SignatureSet;
}

pub type SignatureSet<'a> = crate::generic_signature_set::GenericSignatureSet<
    'a,
    PublicKey,
    AggregatePublicKey,
    Signature,
    AggregateSignature,
>;

pub fn verify_signature_sets<'a>(
    _signature_sets: impl ExactSizeIterator<Item = &'a SignatureSet<'a>>,
) -> bool {
    true
}

#[derive(Clone)]
pub struct PublicKey([u8; PUBLIC_KEY_BYTES_LEN]);

impl PublicKey {
    fn infinity() -> Self {
        Self(INFINITY_PUBLIC_KEY)
    }
}

impl TPublicKey for PublicKey {
    fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        self.0
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let mut pubkey = Self::infinity();
        pubkey.0[..].copy_from_slice(&bytes[0..PUBLIC_KEY_BYTES_LEN]);
        Ok(pubkey)
    }
}

impl Eq for PublicKey {}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

#[derive(Clone)]
pub struct AggregatePublicKey([u8; PUBLIC_KEY_BYTES_LEN]);

impl TAggregatePublicKey<PublicKey> for AggregatePublicKey {
    fn to_public_key(&self) -> GenericPublicKey<PublicKey> {
        GenericPublicKey::from_point(PublicKey(self.0))
    }

    fn aggregate(_pubkeys: &[GenericPublicKey<PublicKey>]) -> Result<Self, Error> {
        Ok(Self(INFINITY_PUBLIC_KEY))
    }
}

impl Eq for AggregatePublicKey {}

impl PartialEq for AggregatePublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

#[derive(Clone)]
pub struct Signature([u8; SIGNATURE_BYTES_LEN]);

impl Signature {
    fn infinity() -> Self {
        Self([0; SIGNATURE_BYTES_LEN])
    }
}

impl TSignature<PublicKey> for Signature {
    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        self.0
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let mut signature = Self::infinity();
        signature.0[..].copy_from_slice(&bytes[0..SIGNATURE_BYTES_LEN]);
        Ok(signature)
    }

    fn verify(&self, _pubkey: &PublicKey, _msg: Hash256) -> bool {
        true
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

#[derive(Clone)]
pub struct AggregateSignature([u8; SIGNATURE_BYTES_LEN]);

impl AggregateSignature {
    fn infinity() -> Self {
        Self(INFINITY_SIGNATURE)
    }
}

impl TAggregateSignature<PublicKey, AggregatePublicKey, Signature> for AggregateSignature {
    fn infinity() -> Self {
        Self::infinity()
    }

    fn add_assign(&mut self, _other: &Signature) {
        // Do nothing.
    }

    fn add_assign_aggregate(&mut self, _other: &Self) {
        // Do nothing.
    }

    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        let mut bytes = [0; SIGNATURE_BYTES_LEN];

        bytes[..].copy_from_slice(&self.0);

        bytes
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let mut key = [0; SIGNATURE_BYTES_LEN];

        key[..].copy_from_slice(bytes);

        Ok(Self(key))
    }

    fn fast_aggregate_verify(
        &self,
        _msg: Hash256,
        _pubkeys: &[&GenericPublicKey<PublicKey>],
    ) -> bool {
        true
    }

    fn aggregate_verify(
        &self,
        _msgs: &[Hash256],
        _pubkeys: &[&GenericPublicKey<PublicKey>],
    ) -> bool {
        true
    }
}

impl Eq for AggregateSignature {}

impl PartialEq for AggregateSignature {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}

#[derive(Clone)]
pub struct SecretKey([u8; SECRET_KEY_BYTES_LEN]);

impl TSecretKey<Signature, PublicKey> for SecretKey {
    fn random() -> Self {
        Self([0; SECRET_KEY_BYTES_LEN])
    }

    fn public_key(&self) -> PublicKey {
        PublicKey::infinity()
    }

    fn sign(&self, _msg: Hash256) -> Signature {
        Signature::infinity()
    }

    fn serialize(&self) -> ZeroizeHash {
        let mut bytes = [0; SECRET_KEY_BYTES_LEN];
        bytes[..].copy_from_slice(&self.0[..]);
        bytes.into()
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let mut sk = Self::random();
        sk.0[..].copy_from_slice(&bytes[0..SECRET_KEY_BYTES_LEN]);
        Ok(sk)
    }
}
