use crate::{
    aggregate_public_key::TAggregatePublicKey,
    aggregate_signature::TAggregateSignature,
    public_key::{PublicKey, TPublicKey, PUBLIC_KEY_BYTES_LEN},
    secret_key::{TSecretKey, SECRET_KEY_BYTES_LEN},
    signature::{TSignature, SIGNATURE_BYTES_LEN},
    Error, Hash256, SecretHash,
};
pub use milagro_bls as milagro;
/*
pub use milagro_bls::{
    AggregatePublicKey as PublicKey, AggregateSignature as Signature, PublicKey as SinglePublicKey,
    SecretKey, Signature as SingleSignature,
};
*/
use rand::thread_rng;

pub const MILAGRO_SECRET_KEY_LEN: usize = 48;

pub type SignatureSet<'a> = crate::signature_set::SignatureSet<
    'a,
    milagro::PublicKey,
    milagro::AggregatePublicKey,
    milagro::Signature,
    milagro::AggregateSignature,
>;

pub fn verify_signature_sets<'a>(
    signature_sets: impl Iterator<Item = &'a SignatureSet<'a>>,
) -> bool {
    let aggregates = signature_sets
        .map(|signature_set| {
            let mut aggregate = milagro::AggregatePublicKey::new();
            for signing_key in &signature_set.signing_keys {
                aggregate.add(signing_key.point())
            }
            // aggregate
            (
                signature_set.signature.as_ref(),
                aggregate,
                signature_set.message,
            )
        })
        .collect::<Vec<_>>();

    /*
    let iter = signature_sets
        .zip(aggregates.iter())
        .map(|(signature_set, aggregate)| {
            (
                signature_set.signature.point().expect("FIXME"),
                aggregate,
                signature_set.message.as_bytes(),
            )
        });
    */

    milagro::AggregateSignature::verify_multiple_aggregate_signatures(
        &mut rand::thread_rng(),
        aggregates.iter().map(|(signature, aggregate, message)| {
            (
                signature.point().expect("FIXME: PAUL H"),
                aggregate,
                message.as_bytes(),
            )
        }), /*
            flattened_sets
                .iter()
                .map(|(signature, aggregate, message)| (*signature, aggregate, message.as_bytes())),
            */
    )
}

impl TPublicKey for milagro::PublicKey {
    fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        let mut bytes = [0; PUBLIC_KEY_BYTES_LEN];
        bytes[..].copy_from_slice(&self.as_bytes());
        bytes
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(&bytes).map_err(Into::into)
    }
}

impl TAggregatePublicKey for milagro::AggregatePublicKey {
    fn zero() -> Self {
        Self::new()
    }
    fn add_assign(&mut self, other: &Self) {
        // Note: this function does not call `self.point.affine()` so signature verification will
        // fail.
        //
        // It is recommended to use `Self::add_assign_multiple` instead.
        self.point.add(&other.point)
    }

    fn add_assign_multiple<'a>(&'a mut self, others: impl Iterator<Item = &'a Self>) {
        others.for_each(|other| self.add_assign(other));
        self.point.affine();
    }

    fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        let mut bytes = [0; PUBLIC_KEY_BYTES_LEN];
        bytes[..].copy_from_slice(&self.as_bytes());
        bytes
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(&bytes).map_err(Into::into)
    }
}

impl TSignature<milagro::PublicKey> for milagro::Signature {
    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        let mut bytes = [0; SIGNATURE_BYTES_LEN];

        bytes[..].copy_from_slice(&self.as_bytes());

        bytes
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        milagro::Signature::from_bytes(&bytes).map_err(|e| Error::MilagroError(e))
    }

    fn verify(&self, pubkey: &milagro::PublicKey, msg: Hash256) -> bool {
        self.verify(msg.as_bytes(), pubkey)
    }
}

impl TAggregateSignature<milagro::PublicKey, milagro::AggregatePublicKey, milagro::Signature>
    for milagro::AggregateSignature
{
    fn zero() -> Self {
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
        milagro::AggregateSignature::from_bytes(&bytes).map_err(|e| Error::MilagroError(e))
    }

    fn fast_aggregate_verify(
        &self,
        msg: Hash256,
        pubkeys: &[&PublicKey<milagro::PublicKey>],
    ) -> bool {
        let pubkeys = pubkeys.iter().map(|pk| pk.point()).collect::<Vec<_>>();
        self.fast_aggregate_verify(msg.as_bytes(), &pubkeys)
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

    fn serialize(&self) -> SecretHash {
        let mut bytes = [0; SECRET_KEY_BYTES_LEN];

        // Takes the right-hand 32 bytes from the secret key.
        bytes[..]
            .copy_from_slice(&self.as_bytes()[MILAGRO_SECRET_KEY_LEN - SECRET_KEY_BYTES_LEN..]);

        bytes.into()
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SECRET_KEY_BYTES_LEN {
            Err(Error::InvalidSecretKeyLength {
                got: bytes.len(),
                expected: SECRET_KEY_BYTES_LEN,
            })
        } else {
            let mut padded = [0; MILAGRO_SECRET_KEY_LEN];
            padded[MILAGRO_SECRET_KEY_LEN - SECRET_KEY_BYTES_LEN..].copy_from_slice(bytes);
            Self::from_bytes(&padded).map_err(Into::into)
        }
    }
}
