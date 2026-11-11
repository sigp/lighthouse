use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::ProgressiveVariableList;
use tree_hash_derive::TreeHash;

use crate::{beacon_state_summary::BeaconStateSummary, core::EthSpec, core::Hash256};

/// Response to a `beacon_state_summary` request: a [`BeaconStateSummary`] plus a Merkle proof
/// (`state_branch`) tying its root to the already-trusted block root the requester started from.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
#[cfg_attr(feature = "arbitrary", arbitrary(bound = "E: EthSpec"))]
pub struct BeaconStateSnapshot<E: EthSpec> {
    pub summary: BeaconStateSummary<E>,
    pub state_branch: ProgressiveVariableList<Hash256>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MinimalEthSpec;

    ssz_and_tree_hash_tests!(BeaconStateSnapshot<MinimalEthSpec>);
}
