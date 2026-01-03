use compare_fields::CompareFields;
use context_deserialize::context_deserialize;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use test_random_derive::TestRandom;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use crate::{
    core::{EthSpec, Hash256},
    fork::ForkName,
    state::BeaconState,
    test_utils::TestRandom,
};

/// `HistoricalSummary` matches the components of the phase0 `HistoricalBatch`
/// making the two hash_tree_root-compatible. This struct is introduced into the beacon state
/// in the Capella hard fork.
///
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/capella/beacon-chain.md#historicalsummary
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Debug,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    TestRandom,
    CompareFields,
    Clone,
    Copy,
    Default,
)]
#[context_deserialize(ForkName)]
pub struct HistoricalSummary {
    block_summary_root: Hash256,
    state_summary_root: Hash256,
}

impl HistoricalSummary {
    pub fn new<E: EthSpec>(state: &BeaconState<E>) -> Self {
        Self {
            block_summary_root: state.block_roots().tree_hash_root(),
            state_summary_root: state.state_roots().tree_hash_root(),
        }
    }
}
