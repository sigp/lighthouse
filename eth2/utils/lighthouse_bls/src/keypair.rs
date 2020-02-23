use crate::{
    public_key::{TPublicKey, PUBLIC_KEY_BYTES_LEN},
    secret_key::{TSecretKey, SECRET_KEY_BYTES_LEN},
    Error,
};
use ssz::{Decode, Encode};
use std::marker::PhantomData;
use tree_hash::TreeHash;

pub const KEYPAIR_BYTES_LEN: usize = PUBLIC_KEY_BYTES_LEN + SECRET_KEY_BYTES_LEN;

pub struct Keypair<PK, SK, Signature> {
    pk: PK,
    sk: SK,
    _phantom: PhantomData<Signature>,
}

impl<PK: TPublicKey, SK: TSecretKey<Signature, PK>, Signature> Keypair<PK, SK, Signature> {
    pub fn random() -> Self {
        let sk = SK::random();
        Self {
            pk: sk.public_key(),
            sk,
            _phantom: PhantomData,
        }
    }

    pub fn serialize(&self) -> [u8; KEYPAIR_BYTES_LEN] {
        let mut bytes = [0; KEYPAIR_BYTES_LEN];
        bytes[..SECRET_KEY_BYTES_LEN].copy_from_slice(&self.sk.serialize());
        bytes[SECRET_KEY_BYTES_LEN..].copy_from_slice(&self.pk.serialize());
        bytes
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() == KEYPAIR_BYTES_LEN {
            Ok(Self {
                sk: SK::deserialize(&bytes[..SECRET_KEY_BYTES_LEN])?,
                pk: PK::deserialize(&bytes[SECRET_KEY_BYTES_LEN..])?,
                _phantom: PhantomData,
            })
        } else {
            Err(Error::InvalidByteLength {
                got: bytes.len(),
                expected: KEYPAIR_BYTES_LEN,
            })
        }
    }
}

impl<PK: TPublicKey, SK: TSecretKey<Signature, PK>, Signature> Encode
    for Keypair<PK, SK, Signature>
{
    impl_ssz_encode!(KEYPAIR_BYTES_LEN);
}

impl<PK: TPublicKey, SK: TSecretKey<Signature, PK>, Signature> Decode
    for Keypair<PK, SK, Signature>
{
    impl_ssz_decode!(KEYPAIR_BYTES_LEN);
}

impl<PK: TPublicKey, SK: TSecretKey<Signature, PK>, Signature> TreeHash
    for Keypair<PK, SK, Signature>
{
    impl_tree_hash!(KEYPAIR_BYTES_LEN);
}
