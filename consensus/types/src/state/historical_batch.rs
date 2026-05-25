use context_deserialize::context_deserialize;
use milhouse::Vector;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::{
    core::{EthSpec, Hash256},
    fork::ForkName,
};

/// Historical block and state roots.
///
/// Spec v0.12.1
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[context_deserialize(ForkName)]
pub struct HistoricalBatch<E: EthSpec> {
    #[cfg_attr(feature = "arbitrary", arbitrary(default))]
    pub block_roots: Vector<Hash256, E::SlotsPerHistoricalRoot>,
    #[cfg_attr(feature = "arbitrary", arbitrary(default))]
    pub state_roots: Vector<Hash256, E::SlotsPerHistoricalRoot>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::MainnetEthSpec;

    pub type FoundationHistoricalBatch = HistoricalBatch<MainnetEthSpec>;

    ssz_and_tree_hash_tests!(FoundationHistoricalBatch);
}
