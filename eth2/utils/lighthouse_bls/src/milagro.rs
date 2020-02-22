use crate::{
    public_key::{TPublicKey, PUBLIC_KEY_BYTES_LEN},
    secret_key::{TSecretKey, SECRET_KEY_BYTES_LEN},
    signature::{TSignature, SIGNATURE_BYTES_LEN},
    Error, MSG_SIZE,
};
pub use milagro_bls::{
    AggregatePublicKey as PublicKey, AggregateSignature, PublicKey as SinglePublicKey, SecretKey,
};
use rand::thread_rng;

impl TPublicKey for PublicKey {
    fn zero() -> Self {
        Self::new()
    }

    fn add_assign(&mut self, other: &Self) {
        self.point.add(&other.point)
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

    fn verify(&self, pubkey: &PublicKey, msg: &[u8]) -> bool {
        if self.is_empty {
            false
        } else {
            self.signature.verify(msg, pubkey)
        }
    }

    fn fast_aggregate_verify(&self, pubkeys: &[PublicKey], msgs: &[[u8; MSG_SIZE]]) -> bool {
        if self.is_empty {
            false
        } else {
            let msg_slices = msgs
                .iter()
                .map(|msg| msg.to_vec())
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
        // This is a bit of a type-level hack since `AggregatePublicKey` doesn't have the method to
        // instantiate from a secret key.
        let point = SinglePublicKey::from_secret_key(self).point;
        PublicKey { point }
    }

    fn sign(&mut self, _msg: &[u8]) -> Signature {
        Signature::zero()
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
