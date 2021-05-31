use crate::ChainSpec;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ForkName {
    Base,
    Altair,
}

impl ForkName {
    pub fn list_all() -> Vec<ForkName> {
        vec![ForkName::Base, ForkName::Altair]
    }

    /// Set the activation slots in the given `ChainSpec` so that the fork named by `self`
    /// is the only fork in effect from genesis.
    pub fn make_genesis_spec(&self, mut spec: ChainSpec) -> ChainSpec {
        match self {
            ForkName::Base => {
                spec.altair_fork_slot = None;
                spec
            }
            ForkName::Altair => {
                spec.altair_fork_slot = Some(spec.genesis_slot);
                spec
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InconsistentFork {
    pub fork_at_slot: ForkName,
    pub object_fork: ForkName,
}
