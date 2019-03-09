use crate::*;
use ssz::SignedRoot;

pub struct TestingVoluntaryExitBuilder {
    exit: VoluntaryExit,
}

impl TestingVoluntaryExitBuilder {
    pub fn new(epoch: Epoch, validator_index: u64) -> Self {
        let exit = VoluntaryExit {
            epoch,
            validator_index,
            signature: Signature::empty_signature(),
        };

        Self { exit }
    }

    pub fn sign(&mut self, secret_key: &SecretKey, fork: &Fork, spec: &ChainSpec) {
        let message = self.exit.signed_root();
        let domain = spec.get_domain(self.exit.epoch, Domain::Exit, fork);

        self.exit.signature = Signature::new(&message, domain, secret_key);
    }

    pub fn build(self) -> VoluntaryExit {
        self.exit
    }
}
