use crate::{ChainSpec, Epoch};

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
        // Assumes GENESIS_EPOCH = 0, which is safe because it's a constant.
        match self {
            ForkName::Base => {
                spec.altair_fork_epoch = None;
                spec
            }
            ForkName::Altair => {
                spec.altair_fork_epoch = Some(Epoch::new(0));
                spec
            }
        }
    }
}

impl std::str::FromStr for ForkName {
    type Err = ();

    fn from_str(fork_name: &str) -> Result<Self, ()> {
        Ok(match fork_name {
            "phase0" | "base" => ForkName::Base,
            "altair" => ForkName::Altair,
            _ => return Err(()),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InconsistentFork {
    pub fork_at_slot: ForkName,
    pub object_fork: ForkName,
}
