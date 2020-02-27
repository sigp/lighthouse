use crate::{
    public_key::{TPublicKey, PUBLIC_KEY_BYTES_LEN},
    secret_key::{TSecretKey, SECRET_KEY_BYTES_LEN},
    signature::{TSignature, SIGNATURE_BYTES_LEN},
    Error, Hash256,
};
pub use milagro_bls::{
    AggregatePublicKey as PublicKey, AggregateSignature as Signature, G1Point,
    PublicKey as SinglePublicKey, SecretKey, Signature as SingleSignature,
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

        // If the given signature does not have a point, that means it's empty. In this case, we'll
        // provide the zero signature.
        let signature_point = set.signature.point().map_or_else(
            || Signature::new().point,
            |signature| signature.point.clone(),
        );

        (signature_point, pubkeys, messages)
    });

    Signature::verify_multiple_signatures(&mut rand::thread_rng(), signatures_iter)
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

impl TSignature<PublicKey> for Signature {
    fn zero() -> Self {
        Signature::new()
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
        Signature::from_bytes(&bytes).map_err(|e| Error::MilagroError(e))
    }

    fn verify(&self, pubkey: &PublicKey, msg: Hash256) -> bool {
        self.verify(msg.as_bytes(), pubkey)
    }

    fn fast_aggregate_verify(&self, pubkeys: &[PublicKey], msgs: &[Hash256]) -> bool {
        let msg_slices = msgs
            .iter()
            .map(|msg| msg.as_bytes().to_vec())
            .collect::<Vec<Vec<u8>>>();
        let pubkey_refs = pubkeys.iter().collect::<Vec<&PublicKey>>();

        self.verify_multiple(&msg_slices[..], &pubkey_refs[..])
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
        Signature { point }
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
