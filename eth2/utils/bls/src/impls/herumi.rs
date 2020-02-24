use crate::{
    public_key::{TPublicKey, PUBLIC_KEY_BYTES_LEN},
    secret_key::{TSecretKey, SECRET_KEY_BYTES_LEN},
    signature::{TSignature, SIGNATURE_BYTES_LEN},
    Error, MSG_SIZE,
};
pub use bls_eth_rust::{PublicKey, SecretKey, Signature};

pub type SignatureSet<'a> = crate::signature_set::SignatureSet<'a, PublicKey, Signature>;

pub fn verify_signature_sets<'a>(signature_sets: impl Iterator<Item = SignatureSet<'a>>) -> bool {
    for set in signature_sets {
        for signed_message in set.signed_messages {
            let pubkeys = signed_message
                .signing_keys
                .into_iter()
                .map(|pubkey| pubkey.point().clone())
                .collect::<Vec<_>>();
            let is_valid = set
                .signature
                .point()
                .fast_aggregate_verify(&pubkeys[..], &signed_message.message[..]);

            if !is_valid {
                return false;
            }
        }
    }

    true
}

impl TPublicKey for PublicKey {
    fn zero() -> Self {
        Self::zero()
    }

    fn add_assign(&mut self, other: &Self) {
        self.add_assign(other)
    }

    fn add_assign_multiple<'a>(&'a mut self, others: impl Iterator<Item = &'a Self>) {
        others.for_each(|other| self.add_assign(other))
    }

    fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        let mut bytes = [0; PUBLIC_KEY_BYTES_LEN];
        bytes[..].copy_from_slice(&self.serialize());
        bytes
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_serialized(bytes).map_err(Into::into)
    }
}

impl TSignature<PublicKey> for Signature {
    fn zero() -> Self {
        Self::zero()
    }

    fn add_assign(&mut self, other: &Self) {
        self.add_assign(other)
    }

    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        let mut bytes = [0; SIGNATURE_BYTES_LEN];
        bytes[..].copy_from_slice(&self.serialize());
        bytes
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_serialized(bytes).map_err(Into::into)
    }

    fn verify(&self, pubkey: &PublicKey, msg: &[u8]) -> bool {
        self.verify(pubkey, msg)
    }

    fn fast_aggregate_verify(&self, pubkeys: &[PublicKey], msgs: &[[u8; MSG_SIZE]]) -> bool {
        let msg = msgs
            .iter()
            .map(|a| a.to_vec())
            .flatten()
            .collect::<Vec<_>>();

        self.fast_aggregate_verify(pubkeys, &msg)
    }
}

impl TSecretKey<Signature, PublicKey> for SecretKey {
    fn random() -> Self {
        let mut sk = Self::default();
        sk.set_by_csprng();
        sk
    }

    fn public_key(&self) -> PublicKey {
        self.get_publickey()
    }

    fn sign(&self, msg: &[u8]) -> Signature {
        SecretKey::sign(self, msg)
    }

    fn serialize(&self) -> [u8; SECRET_KEY_BYTES_LEN] {
        let mut bytes = [0; SECRET_KEY_BYTES_LEN];
        bytes[..].copy_from_slice(&self.serialize());
        bytes
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_serialized(bytes).map_err(Into::into)
    }
}
