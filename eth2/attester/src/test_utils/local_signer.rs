use crate::traits::Signer;
use std::sync::RwLock;
use types::{Keypair, Signature};

/// A test-only struct used to simulate a Beacon Node.
pub struct LocalSigner {
    keypair: Keypair,
    should_sign: RwLock<bool>,
}

impl LocalSigner {
    /// Produce a new LocalSigner with signing enabled by default.
    pub fn new(keypair: Keypair) -> Self {
        Self {
            keypair,
            should_sign: RwLock::new(true),
        }
    }

    /// If set to `false`, the service will refuse to sign all messages. Otherwise, all messages
    /// will be signed.
    pub fn enable_signing(&self, enabled: bool) {
        *self.should_sign.write().unwrap() = enabled;
    }
}

impl Signer for LocalSigner {
    fn sign_attestation_message(&self, message: &[u8]) -> Option<Signature> {
        Some(Signature::new(message, &self.keypair.sk))
    }
}
