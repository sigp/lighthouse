use crate::{
    generic_public_key::{GenericPublicKey, TPublicKey},
    generic_secret_key::{GenericSecretKey, TSecretKey},
    generic_signature::TSignature,
};
use std::fmt;
use std::marker::PhantomData;

/// A simple wrapper around `PublicKey` and `GenericSecretKey`.
#[derive(Clone)]
pub struct GenericKeypair<Pub, Sec, Sig> {
    pub pk: GenericPublicKey<Pub>,
    pub sk: GenericSecretKey<Sig, Pub, Sec>,
    _phantom: PhantomData<Sig>,
}

impl<Pub, Sec, Sig> GenericKeypair<Pub, Sec, Sig>
where
    Pub: TPublicKey,
    Sec: TSecretKey<Sig, Pub>,
    Sig: TSignature<Pub>,
{
    /// Instantiate `Self` from a public and secret key.
    ///
    /// This function does not check to ensure that `pk` is derived from `sk`. It would be a logic
    /// error to supply such a `pk`.
    pub fn from_components(pk: GenericPublicKey<Pub>, sk: GenericSecretKey<Sig, Pub, Sec>) -> Self {
        Self {
            pk,
            sk,
            _phantom: PhantomData,
        }
    }

    /// Instantiates `Self` from a randomly generated secret key.
    pub fn random() -> Self {
        let sk = GenericSecretKey::random();
        Self {
            pk: sk.public_key(),
            sk,
            _phantom: PhantomData,
        }
    }
}

impl<Pub, Sec, Sig> fmt::Debug for GenericKeypair<Pub, Sec, Sig>
where
    Pub: TPublicKey,
{
    /// Defers to `self.pk` to avoid leaking the secret key.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.pk.fmt(f)
    }
}
