use crate::*;
use tree_hash::SignedRoot;

/// Builds an exit to be used for testing purposes.
///
/// This struct should **never be used for production purposes.**
pub struct TestingVoluntaryExitBuilder {
    exit: VoluntaryExit,
}

impl TestingVoluntaryExitBuilder {
    /// Instantiates a new builder.
    pub fn new(epoch: Epoch, validator_index: u64) -> Self {
        let exit = VoluntaryExit {
            epoch,
            validator_index,
            signature: Signature::empty_signature(),
        };

        Self { exit }
    }

    /// Signs the exit.
    ///
    /// The signing secret key must match that of the exiting validator.
    pub fn sign(&mut self, secret_key: &SecretKey, fork: &Fork, spec: &ChainSpec) {
        let message = self.exit.signed_root();
        let domain = spec.get_domain(self.exit.epoch, Domain::VoluntaryExit, fork);

        self.exit.signature = Signature::new(&message, domain, secret_key);
    }

    /// Builds the exit, consuming the builder.
    pub fn build(self) -> VoluntaryExit {
        self.exit
    }
}
