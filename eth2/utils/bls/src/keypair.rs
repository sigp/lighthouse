use crate::{
    public_key::{PublicKey, TPublicKey, PUBLIC_KEY_BYTES_LEN},
    secret_key::{SecretKey, TSecretKey, SECRET_KEY_BYTES_LEN},
    signature::TSignature,
    Error,
};
use ssz::{Decode, Encode};
use std::marker::PhantomData;
use tree_hash::TreeHash;

pub const KEYPAIR_BYTES_LEN: usize = PUBLIC_KEY_BYTES_LEN + SECRET_KEY_BYTES_LEN;

#[derive(Clone, PartialEq)]
pub struct Keypair<Pub, Sec, Sig> {
    pub pk: PublicKey<Pub>,
    pub sk: SecretKey<Sig, Pub, Sec>,
    _phantom: PhantomData<Sig>,
}

impl<Pub, Sec, Sig> Keypair<Pub, Sec, Sig>
where
    Pub: TPublicKey,
    Sec: TSecretKey<Sig, Pub>,
    Sig: TSignature<Pub>,
{
    pub fn from_components(pk: PublicKey<Pub>, sk: SecretKey<Sig, Pub, Sec>) -> Self {
        Self {
            pk,
            sk,
            _phantom: PhantomData,
        }
    }

    pub fn random() -> Self {
        let sk = SecretKey::random();
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
                sk: SecretKey::deserialize(&bytes[..SECRET_KEY_BYTES_LEN])?,
                pk: PublicKey::deserialize(&bytes[SECRET_KEY_BYTES_LEN..])?,
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

impl<Pub, Sec, Sig> Encode for Keypair<Pub, Sec, Sig>
where
    Pub: TPublicKey,
    Sec: TSecretKey<Sig, Pub>,
    Sig: TSignature<Pub>,
{
    impl_ssz_encode!(KEYPAIR_BYTES_LEN);
}

impl<Pub, Sec, Sig> Decode for Keypair<Pub, Sec, Sig>
where
    Pub: TPublicKey,
    Sec: TSecretKey<Sig, Pub>,
    Sig: TSignature<Pub>,
{
    impl_ssz_decode!(KEYPAIR_BYTES_LEN);
}

impl<Pub, Sec, Sig> TreeHash for Keypair<Pub, Sec, Sig>
where
    Pub: TPublicKey,
    Sec: TSecretKey<Sig, Pub>,
    Sig: TSignature<Pub>,
{
    impl_tree_hash!(KEYPAIR_BYTES_LEN);
}
