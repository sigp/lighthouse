use crate::{
    public_key::{TPublicKey, PUBLIC_KEY_BYTES_LEN},
    secret_key::{TSecretKey, SECRET_KEY_BYTES_LEN},
    signature::{TSignature, SIGNATURE_BYTES_LEN},
    Error, Hash256,
};
pub use milagro_bls::{
    AggregatePublicKey as PublicKey, AggregateSignature, G1Point, PublicKey as SinglePublicKey,
    SecretKey, Signature as SingleSignature,
};
use rand::thread_rng;

pub type SignatureSet<'a> = crate::signature_set::SignatureSet<'a, PublicKey, Signature>;
pub type SignedMessage<'a> = crate::signature_set::SignedMessage<'a, PublicKey>;

pub fn verify_signature_sets<'a>(signature_sets: impl Iterator<Item = SignatureSet<'a>>) -> bool {
    let signatures_iter = signature_sets.map(|set| {
        let (pubkeys, messages): (Vec<G1Point>, Vec<Vec<u8>>) = set
            .signed_messages
            .into_iter()
            .map(|signed_message| {
                let key = if signed_message.signing_keys.len() == 1 {
                    signed_message.signing_keys[0].point().clone()
                } else {
                    let mut aggregate = PublicKey::new();
                    for signing_key in signed_message.signing_keys {
                        aggregate.add(&SinglePublicKey {
                            point: signing_key.point().point.clone(),
                        })
                    }
                    aggregate
                };

                (key.point, signed_message.message.as_bytes().to_vec())
            })
            .unzip();

        (
            set.signature.point().signature.point.clone(),
            pubkeys,
            messages,
        )
    });

    AggregateSignature::verify_multiple_signatures(&mut rand::thread_rng(), signatures_iter)
}

impl TPublicKey for PublicKey {
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

#[derive(Clone, PartialEq)]
pub struct Signature {
    signature: AggregateSignature,
    // TODO: make this an option.
    is_empty: bool,
}

impl TSignature<PublicKey> for Signature {
    fn zero() -> Self {
        Self {
            signature: AggregateSignature::new(),
            // The `zero()` function creates a signature at the zero point, _not_ from all zero
            // bytes. Only a signature with all zero bytes is considered "empty".
            is_empty: false,
        }
    }

    fn add_assign(&mut self, other: &Self) {
        if !self.is_empty {
            self.signature.add_aggregate(&other.signature)
        }
    }

    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        let mut bytes = [0; SIGNATURE_BYTES_LEN];

        if !self.is_empty {
            bytes[..].copy_from_slice(&self.signature.as_bytes());
        }

        bytes
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        for byte in bytes {
            if *byte != 0 || bytes.len() != SIGNATURE_BYTES_LEN {
                return Ok(Self {
                    signature: AggregateSignature::from_bytes(&bytes)
                        .map_err(|e| Error::MilagroError(e))?,
                    is_empty: false,
                });
            }
        }

        Ok(Self {
            signature: AggregateSignature::new(),
            is_empty: true,
        })
    }

    fn verify(&self, pubkey: &PublicKey, msg: Hash256) -> bool {
        if self.is_empty {
            false
        } else {
            self.signature.verify(msg.as_bytes(), pubkey)
        }
    }

    fn fast_aggregate_verify(&self, pubkeys: &[PublicKey], msgs: &[Hash256]) -> bool {
        if self.is_empty {
            false
        } else {
            let msg_slices = msgs
                .iter()
                .map(|msg| msg.as_bytes().to_vec())
                .collect::<Vec<Vec<u8>>>();
            let pubkey_refs = pubkeys.iter().collect::<Vec<&PublicKey>>();

            self.signature
                .verify_multiple(&msg_slices[..], &pubkey_refs[..])
        }
    }
}

impl TSecretKey<Signature, PublicKey> for SecretKey {
    fn random() -> Self {
        Self::random(&mut thread_rng())
    }

    fn public_key(&self) -> PublicKey {
        let point = SinglePublicKey::from_secret_key(self).point;
        PublicKey { point }
    }

    fn sign(&self, msg: Hash256) -> Signature {
        let point = SingleSignature::new(msg.as_bytes(), self).point;
        Signature {
            signature: AggregateSignature { point },
            is_empty: false,
        }
    }

    fn serialize(&self) -> [u8; SECRET_KEY_BYTES_LEN] {
        let mut bytes = [0; SECRET_KEY_BYTES_LEN];
        bytes[..].copy_from_slice(&self.as_bytes());
        bytes
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(&bytes).map_err(Into::into)
    }
}
