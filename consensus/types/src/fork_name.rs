use crate::{ChainSpec, Slot};

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

    /// Returns the `ForkName` given the slot and depending if Altair is enabled in the `ChainSpec`.
    pub fn from_slot(slot: Slot, spec: &ChainSpec) -> Self {
        if let Some(altair_fork_slot) = spec.altair_fork_slot {
            if slot >= altair_fork_slot {
                ForkName::Altair
            } else {
                ForkName::Base
            }
        } else {
            ForkName::Base
        }
    }
}
