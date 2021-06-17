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

    /// Return the name of the fork immediately prior to the current one.
    ///
    /// If `self` is `ForkName::Base` then `Base` is returned.
    pub fn previous_fork(self) -> Option<ForkName> {
        match self {
            ForkName::Base => None,
            ForkName::Altair => Some(ForkName::Base),
        }
    }

    /// Return the name of the fork immediately after the current one.
    ///
    /// If `self` is the last known fork and has no successor, `None` is returned.
    pub fn next_fork(self) -> Option<ForkName> {
        match self {
            ForkName::Base => Some(ForkName::Altair),
            ForkName::Altair => None,
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

#[cfg(test)]
mod test {
    use super::*;
    use itertools::Itertools;

    #[test]
    fn previous_and_next_fork_consistent() {
        assert_eq!(ForkName::Altair.next_fork(), None);
        assert_eq!(ForkName::Base.previous_fork(), None);

        for (prev_fork, fork) in ForkName::list_all().into_iter().tuple_windows() {
            assert_eq!(prev_fork.next_fork(), Some(fork));
            assert_eq!(fork.previous_fork(), Some(prev_fork));
        }
    }
}
