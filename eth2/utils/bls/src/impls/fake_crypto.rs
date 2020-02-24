use crate::{
    public_key::{TPublicKey, PUBLIC_KEY_BYTES_LEN},
    secret_key::{TSecretKey, SECRET_KEY_BYTES_LEN},
    signature::{TSignature, SIGNATURE_BYTES_LEN},
    Error, MSG_SIZE,
};

pub struct PublicKey([u8; PUBLIC_KEY_BYTES_LEN]);

impl TPublicKey for PublicKey {
    fn zero() -> Self {
        Self([0; PUBLIC_KEY_BYTES_LEN])
    }

    fn add_assign(&mut self, _other: &Self) {
        // Do nothing.
    }

    fn add_assign_multiple<'a>(&'a mut self, _others: impl Iterator<Item = &'a Self>) {
        // Do nothing.
    }

    fn serialize(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        self.0.clone()
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let mut pubkey = Self::zero();
        pubkey.0[..].copy_from_slice(&bytes[0..PUBLIC_KEY_BYTES_LEN]);
        Ok(pubkey)
    }
}

pub struct Signature([u8; SIGNATURE_BYTES_LEN]);

impl TSignature<PublicKey> for Signature {
    fn zero() -> Self {
        Self([0; SIGNATURE_BYTES_LEN])
    }

    fn add_assign(&mut self, _other: &Self) {
        // Do nothing.
    }

    fn serialize(&self) -> [u8; SIGNATURE_BYTES_LEN] {
        self.0.clone()
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let mut signature = Self::zero();
        signature.0[..].copy_from_slice(&bytes[0..SIGNATURE_BYTES_LEN]);
        Ok(signature)
    }

    fn verify(&self, _pubkey: &PublicKey, _msg: &[u8]) -> bool {
        true
    }

    fn fast_aggregate_verify(&self, _pubkeys: &[PublicKey], _msgs: &[[u8; MSG_SIZE]]) -> bool {
        true
    }
}

pub struct SecretKey([u8; SECRET_KEY_BYTES_LEN]);

impl TSecretKey<Signature, PublicKey> for SecretKey {
    fn random() -> Self {
        Self([0; SECRET_KEY_BYTES_LEN])
    }

    fn public_key(&self) -> PublicKey {
        PublicKey::zero()
    }

    fn sign(&self, _msg: &[u8]) -> Signature {
        Signature::zero()
    }

    fn serialize(&self) -> [u8; SECRET_KEY_BYTES_LEN] {
        let mut bytes = [0; SECRET_KEY_BYTES_LEN];
        bytes[..].copy_from_slice(&self.0[..]);
        bytes
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let mut sk = Self::random();
        sk.0[..].copy_from_slice(&bytes[0..SECRET_KEY_BYTES_LEN]);
        Ok(sk)
    }
}
