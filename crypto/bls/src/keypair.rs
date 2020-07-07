use crate::{
    public_key::{PublicKey, TPublicKey},
    secret_key::{SecretKey, TSecretKey},
    signature::TSignature,
};
use std::fmt;
use std::marker::PhantomData;

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
}

impl<Pub, Sec, Sig> fmt::Debug for Keypair<Pub, Sec, Sig>
where
    Pub: TPublicKey,
{
    /// Defers to `self.pk` to avoid leaking the secret key.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.pk.fmt(f)
    }
}
