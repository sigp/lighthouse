use std::fmt::Display;
use types::{Keypair, PublicKey, Signature};

/// Signs message using an internally-maintained private key.
pub trait Signer: Display + Send + Sync + Clone {
    fn sign_message(&self, message: &[u8], domain: u64) -> Option<Signature>;
    /// Returns a public key for the signer object.
    fn to_public(&self) -> PublicKey;
}

/* Implements Display and Signer for Keypair */

impl Signer for Keypair {
    fn to_public(&self) -> PublicKey {
        self.pk.clone()
    }

    fn sign_message(&self, message: &[u8], domain: u64) -> Option<Signature> {
        Some(Signature::new(message, domain, &self.sk))
    }
}
