use crate::{
    aggregate_public_key::TAggregatePublicKey,
    aggregate_signature::TAggregateSignature,
    public_key::{PublicKey, TPublicKey, PUBLIC_KEY_BYTES_LEN},
    secret_key::{TSecretKey, SECRET_KEY_BYTES_LEN},
    signature::{TSignature, SIGNATURE_BYTES_LEN},
    Error, Hash256, SecretHash,
};
pub use milagro_bls as milagro;
use std::iter::ExactSizeIterator;
/*
pub use milagro_bls::{
    AggregatePublicKey as PublicKey, AggregateSignature as Signature, PublicKey as SinglePublicKey,
    SecretKey, Signature as SingleSignature,
};
*/
use rand::thread_rng;

pub type SignatureSet<'a> = crate::signature_set::SignatureSet<
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
        self.point.add(&other.point);
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

    fn aggregate_verify(
        &self,
        msgs: &[Hash256],
        pubkeys: &[&PublicKey<milagro::PublicKey>],
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

    fn serialize(&self) -> SecretHash {
        let mut bytes = [0; SECRET_KEY_BYTES_LEN];

        // Takes the right-hand 32 bytes from the secret key.
        bytes[..].copy_from_slice(&self.as_bytes());

        bytes.into()
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(&bytes).map_err(Into::into)
    }
}
