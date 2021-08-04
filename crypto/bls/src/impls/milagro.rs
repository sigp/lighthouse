use crate::{
    generic_aggregate_public_key::TAggregatePublicKey,
    generic_aggregate_signature::TAggregateSignature,
    generic_public_key::{GenericPublicKey, TPublicKey, PUBLIC_KEY_BYTES_LEN},
    generic_secret_key::{TSecretKey, SECRET_KEY_BYTES_LEN},
    generic_signature::{TSignature, SIGNATURE_BYTES_LEN},
    Error, Hash256, ZeroizeHash,
};
pub use milagro_bls as milagro;
use rand::thread_rng;
use std::iter::ExactSizeIterator;

/// Provides the externally-facing, core BLS types.
pub mod types {
    pub use super::milagro::AggregatePublicKey;
    pub use super::milagro::AggregateSignature;
    pub use super::milagro::PublicKey;
    pub use super::milagro::SecretKey;
    pub use super::milagro::Signature;
    pub use super::verify_signature_sets;
    pub use super::SignatureSet;
}

pub type SignatureSet<'a> = crate::generic_signature_set::GenericSignatureSet<
    'a,
    milagro::PublicKey,
    milagro::AggregatePublicKey,
    milagro::Signature,
    milagro::AggregateSignature,
>;

pub fn verify_signature_sets<'a>(
    signature_sets: impl ExactSizeIterator<Item = &'a SignatureSet<'a>>,
) -> bool {
    if signature_sets.len() == 0 {
        return false;
    }

    signature_sets
        .map(|signature_set| {
            let mut aggregate = milagro::AggregatePublicKey::from_public_key(
                signature_set.signing_keys.first().ok_or(())?.point(),
            );

            for signing_key in signature_set.signing_keys.iter().skip(1) {
                aggregate.add(signing_key.point())
            }

            if signature_set.signature.point().is_none() {
                return Err(());
            }

            Ok((
                signature_set.signature.as_ref(),
                aggregate,
                signature_set.message,
            ))
        })
        .collect::<Result<Vec<_>, ()>>()
        .map(|aggregates| {
            milagro::AggregateSignature::verify_multiple_aggregate_signatures(
                &mut rand::thread_rng(),
                aggregates.iter().map(|(signature, aggregate, message)| {
                    (
                        signature
                            .point()
                            .expect("guarded against none by previous check"),
                        aggregate,
                        message.as_bytes(),
                    )
                }),
            )
        })
        .unwrap_or(false)
}

impl TPublicKey for milagro::PublicKey {
    fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        let mut bytes = [0; PUBLIC_KEY_BYTES_LEN];
        bytes[..].copy_from_slice(&self.as_bytes());
        bytes
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(bytes).map_err(Into::into)
    }
}

impl TAggregatePublicKey<milagro::PublicKey> for milagro::AggregatePublicKey {
    fn to_public_key(&self) -> GenericPublicKey<milagro::PublicKey> {
        GenericPublicKey::from_point(milagro::PublicKey {
            point: self.point.clone(),
        })
    }

    fn aggregate(pubkeys: &[GenericPublicKey<milagro::PublicKey>]) -> Result<Self, Error> {
        let pubkey_refs = pubkeys.iter().map(|pk| pk.point()).collect::<Vec<_>>();
        Ok(milagro::AggregatePublicKey::aggregate(&pubkey_refs)?)
    }
}

impl TSignature<milagro::PublicKey> for milagro::Signature {
    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        let mut bytes = [0; SIGNATURE_BYTES_LEN];

        bytes[..].copy_from_slice(&self.as_bytes());

        bytes
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        milagro::Signature::from_bytes(&bytes).map_err(Error::MilagroError)
    }

    fn verify(&self, pubkey: &milagro::PublicKey, msg: Hash256) -> bool {
        self.verify(msg.as_bytes(), pubkey)
    }
}

impl TAggregateSignature<milagro::PublicKey, milagro::AggregatePublicKey, milagro::Signature>
    for milagro::AggregateSignature
{
    fn infinity() -> Self {
        milagro::AggregateSignature::new()
    }

    fn add_assign(&mut self, other: &milagro::Signature) {
        self.add(other)
    }

    fn add_assign_aggregate(&mut self, other: &Self) {
        self.add_aggregate(other)
    }

    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        let mut bytes = [0; SIGNATURE_BYTES_LEN];

        bytes[..].copy_from_slice(&self.as_bytes());

        bytes
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        milagro::AggregateSignature::from_bytes(&bytes).map_err(Error::MilagroError)
    }

    fn fast_aggregate_verify(
        &self,
        msg: Hash256,
        pubkeys: &[&GenericPublicKey<milagro::PublicKey>],
    ) -> bool {
        let pubkeys = pubkeys.iter().map(|pk| pk.point()).collect::<Vec<_>>();
        self.fast_aggregate_verify(msg.as_bytes(), &pubkeys)
    }

    fn aggregate_verify(
        &self,
        msgs: &[Hash256],
        pubkeys: &[&GenericPublicKey<milagro::PublicKey>],
    ) -> bool {
        let pubkeys = pubkeys.iter().map(|pk| pk.point()).collect::<Vec<_>>();
        let msgs = msgs.iter().map(|hash| hash.as_bytes()).collect::<Vec<_>>();
        self.aggregate_verify(&msgs, &pubkeys)
    }
}

impl TSecretKey<milagro::Signature, milagro::PublicKey> for milagro::SecretKey {
    fn random() -> Self {
        Self::random(&mut thread_rng())
    }

    fn public_key(&self) -> milagro::PublicKey {
        let point = milagro::PublicKey::from_secret_key(self).point;
        milagro::PublicKey { point }
    }

    fn sign(&self, msg: Hash256) -> milagro::Signature {
        let point = milagro::Signature::new(msg.as_bytes(), self).point;
        milagro::Signature { point }
    }

    fn serialize(&self) -> ZeroizeHash {
        let mut bytes = [0; SECRET_KEY_BYTES_LEN];

        // Takes the right-hand 32 bytes from the secret key.
        bytes[..].copy_from_slice(&self.as_bytes());

        bytes.into()
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(bytes).map_err(Into::into)
    }
}
