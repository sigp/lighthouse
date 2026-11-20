use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::ProgressiveVariableList;
use tree_hash_derive::TreeHash;

use crate::core::Hash256;

/// One fetchable slice of state data, returned by `beacon_state_parts_by_range`: the chunk's
/// index, its raw bytes, and a Merkle proof (`branch`) tying it to an already-verified
/// [`super::BeaconStateSnapshot`] summary root. Different chunks can be fetched from different,
/// mutually untrusting peers and verified independently.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[serde(deny_unknown_fields)]
pub struct BeaconStatePart {
    #[serde(with = "serde_utils::quoted_u64")]
    pub chunk_index: u64,
    pub data: ProgressiveVariableList<u8>,
    pub branch: ProgressiveVariableList<Hash256>,
}

#[cfg(test)]
mod tests {
    use super::*;

    ssz_and_tree_hash_tests!(BeaconStatePart);
}
