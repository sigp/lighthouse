use attester::Signer as AttesterSigner;
use block_producer::Signer as BlockProposerSigner;
use std::sync::RwLock;
use types::{Keypair, Signature};

/// A test-only struct used to simulate a Beacon Node.
pub struct TestSigner {
    keypair: Keypair,
    should_sign: RwLock<bool>,
}

impl TestSigner {
    /// Produce a new TestSigner with signing enabled by default.
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

    fn bls_sign(&self, message: &[u8]) -> Option<Signature> {
        Some(Signature::new(message, &self.keypair.sk))
    }
}

impl BlockProposerSigner for TestSigner {
    fn sign_block_proposal(&self, message: &[u8]) -> Option<Signature> {
        self.bls_sign(message)
    }

    fn sign_randao_reveal(&self, message: &[u8]) -> Option<Signature> {
        self.bls_sign(message)
    }
}

impl AttesterSigner for TestSigner {
    fn sign_attestation_message(&self, message: &[u8]) -> Option<Signature> {
        self.bls_sign(message)
    }
}
