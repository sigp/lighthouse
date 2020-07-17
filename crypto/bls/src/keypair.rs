use crate::{
    public_key::{PublicKey, TPublicKey},
    secret_key::{SecretKey, TSecretKey},
    signature::TSignature,
};
use std::fmt;
use std::marker::PhantomData;

/// A simple wrapper around `PublicKey` and `SecretKey`.
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
    /// Instantiate `Self` from a public and secret key.
    ///
    /// This function does not check to ensure that `pk` is derived from `sk`. It would be a logic
    /// error to supply such a `pk`.
    pub fn from_components(pk: PublicKey<Pub>, sk: SecretKey<Sig, Pub, Sec>) -> Self {
        Self {
            pk,
            sk,
            _phantom: PhantomData,
        }
    }

    /// Instantiates `Self` from a randomly generated secret key.
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
