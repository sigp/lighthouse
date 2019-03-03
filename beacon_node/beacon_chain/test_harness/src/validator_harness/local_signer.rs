use attester::Signer as AttesterSigner;
use block_proposer::Signer as BlockProposerSigner;
use types::{Keypair, Signature};

/// A test-only struct used to perform signing for a proposer or attester.
pub struct LocalSigner {
    keypair: Keypair,
}

impl LocalSigner {
    /// Produce a new TestSigner with signing enabled by default.
    pub fn new(keypair: Keypair) -> Self {
        Self { keypair }
    }

    /// Sign some message.
    fn bls_sign(&self, message: &[u8], domain: u64) -> Option<Signature> {
        Some(Signature::new(message, domain, &self.keypair.sk))
    }
}

impl BlockProposerSigner for LocalSigner {
    fn sign_block_proposal(&self, message: &[u8], domain: u64) -> Option<Signature> {
        self.bls_sign(message, domain)
    }

    fn sign_randao_reveal(&self, message: &[u8], domain: u64) -> Option<Signature> {
        self.bls_sign(message, domain)
    }
}

impl AttesterSigner for LocalSigner {
    fn sign_attestation_message(&self, message: &[u8], domain: u64) -> Option<Signature> {
        self.bls_sign(message, domain)
    }
}
