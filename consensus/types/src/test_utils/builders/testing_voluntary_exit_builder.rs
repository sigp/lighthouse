use crate::*;

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
        };

        Self { exit }
    }

    /// Build and sign the exit.
    ///
    /// The signing secret key must match that of the exiting validator.
    pub fn build(
        self,
        secret_key: &SecretKey,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> SignedVoluntaryExit {
        self.exit
            .sign(secret_key, fork, genesis_validators_root, spec)
    }
}
