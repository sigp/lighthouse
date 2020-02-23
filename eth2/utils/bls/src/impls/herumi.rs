use crate::{
    public_key::{TPublicKey, PUBLIC_KEY_BYTES_LEN},
    secret_key::{TSecretKey, SECRET_KEY_BYTES_LEN},
    signature::{TSignature, SIGNATURE_BYTES_LEN},
    Error, MSG_SIZE,
};
pub use bls_eth_rust::{PublicKey, SecretKey, Signature};

impl TPublicKey for PublicKey {
    fn zero() -> Self {
        Self::zero()
    }

    fn add_assign(&mut self, other: &Self) {
        self.add_assign(other)
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
