use crate::{
    public_key::{TPublicKey, PUBLIC_KEY_BYTES_LEN},
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
    milagro::AggregatePublicKey,
    milagro::AggregateSignature,
>;
pub type SignedMessage<'a> = crate::signature_set::SignedMessage<'a, milagro::AggregatePublicKey>;

pub fn verify_signature_sets<'a>(signature_sets: impl Iterator<Item = SignatureSet<'a>>) -> bool {
    /*
    let rng = &mut rand::thread_rng();
    let verify_set: Vec<VerifySet> = signature_sets
        .map(|ss| (&ss.signature, &ss.signing_keys, ss.message.as_slice()))
        .collect();
    milagro::AggregateSignature::verify_multiple_aggregate_signatures(rng, verify_set.into_iter())
    */

    let flattened_sets = signature_sets
        .map(|signature_set| {
            let signature = signature_set.signature.point().expect("FIXME");

            signature_set
                .signed_messages
                .into_iter()
                .map(move |signed_message| {
                    let mut aggregate = milagro::AggregatePublicKey::new();
                    for signing_key in &signed_message.signing_keys {
                        aggregate.add(&milagro::PublicKey {
                            // TODO: address this expensive clone.
                            point: signing_key.point().point.clone(),
                        })
                    }

                    (signature, aggregate, signed_message.message)
                })
        })
        .flatten()
        .collect::<Vec<(
            &milagro::AggregateSignature,
            milagro::AggregatePublicKey,
            Hash256,
        )>>();

    /*
    let signatures_iter = signature_sets.map(|set| {
        let (pubkeys, messages): (Vec<milagro::AggregatePublicKey>, Vec<Vec<u8>>) = set
            .signed_messages
            .into_iter()
            .map(|signed_message| {
                let key = if signed_message.signing_keys.len() == 1 {
                    signed_message.signing_keys[0].point().clone()
                } else {
                    let mut aggregate = milagro::AggregatePublicKey::new();
                    for signing_key in signed_message.signing_keys {
                        aggregate.add(&milagro::PublicKey {
                            // TODO: address this expensive clone.
                            point: signing_key.point().point.clone(),
                        })
                    }
                    aggregate
                };

                (key, signed_message.message.as_bytes().to_vec())
            })
            .unzip();

        /*
        // If the given signature does not have a point, that means it's empty. In this case, we'll
        // provide the zero signature.
        let signature_point = set.signature.point().map_or_else(
            || Signature::new().point,
            |signature| signature.point.clone(),
        );
        */

        (set.signature.point().expect("FIXME"), pubkeys, messages)
    });
    */

    milagro::AggregateSignature::verify_multiple_aggregate_signatures(
        &mut rand::thread_rng(),
        flattened_sets
            .iter()
            .map(|(signature, aggregate, message)| (*signature, aggregate, message.as_bytes())),
    )
}

impl TPublicKey for milagro::AggregatePublicKey {
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

impl TSignature<milagro::AggregatePublicKey> for milagro::AggregateSignature {
    fn zero() -> Self {
        milagro::AggregateSignature::new()
    }

    fn add_assign(&mut self, other: &Self) {
        self.add_aggregate(&other)
    }

    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        let mut bytes = [0; SIGNATURE_BYTES_LEN];

        bytes[..].copy_from_slice(&self.as_bytes());

        bytes
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        milagro::AggregateSignature::from_bytes(&bytes).map_err(|e| Error::MilagroError(e))
    }

    fn verify(&self, pubkey: &milagro::AggregatePublicKey, msg: Hash256) -> bool {
        self.fast_aggregate_verify_pre_aggregated(msg.as_bytes(), pubkey)
    }

    fn fast_aggregate_verify(
        &self,
        pubkeys: &[milagro::AggregatePublicKey],
        msgs: &[Hash256],
    ) -> bool {
        todo!("fast_aggregate_verify")
        /*
        let msg_slices = msgs
            .iter()
            .map(|msg| msg.as_bytes().to_vec())
            .collect::<Vec<Vec<u8>>>();
        let pubkey_refs = pubkeys
            .iter()
            .collect::<Vec<&milagro::AggregatePublicKey>>();

        self.verify_multiple(&msg_slices[..], &pubkey_refs[..])
        */
    }
}

impl TSecretKey<milagro::AggregateSignature, milagro::AggregatePublicKey> for milagro::SecretKey {
    fn random() -> Self {
        Self::random(&mut thread_rng())
    }

    fn public_key(&self) -> milagro::AggregatePublicKey {
        let point = milagro::PublicKey::from_secret_key(self).point;
        milagro::AggregatePublicKey {
            point,
            is_empty: false,
        }
    }

    fn sign(&self, msg: Hash256) -> milagro::AggregateSignature {
        let point = milagro::Signature::new(msg.as_bytes(), self).point;
        milagro::AggregateSignature { point }
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
