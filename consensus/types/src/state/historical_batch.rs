use context_deserialize::context_deserialize;
use milhouse::Vector;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::{
    core::{Hash256, Spec},
    fork::ForkName,
};

/// Historical block and state roots.
///
/// Spec v0.12.1
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct HistoricalBatch {
    #[cfg_attr(feature = "arbitrary", arbitrary(default))]
    pub block_roots: Vector<Hash256, typenum::U<{ Spec::SLOTS_PER_HISTORICAL_ROOT }>>,
    #[cfg_attr(feature = "arbitrary", arbitrary(default))]
    pub state_roots: Vector<Hash256, typenum::U<{ Spec::SLOTS_PER_HISTORICAL_ROOT }>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(HistoricalBatch);
}
