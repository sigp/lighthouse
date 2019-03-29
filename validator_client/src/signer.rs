use types::Signature;

/// Signs message using an internally-maintained private key.
pub trait Signer {
    fn sign_block_proposal(&self, message: &[u8], domain: u64) -> Option<Signature>;
    fn sign_randao_reveal(&self, message: &[u8], domain: u64) -> Option<Signature>;
}
