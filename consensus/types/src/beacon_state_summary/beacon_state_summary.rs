use std::sync::Arc;

use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::{BitVector, FixedVector};
use tree_hash_derive::TreeHash;

use crate::{
    ExecutionBlockHash, ExecutionPayloadBid, Fork,
    attestation::Checkpoint,
    beacon_state_summary::ListSummary,
    block::BeaconBlockHeader,
    builder::{BuilderIndex, BuilderPendingPayment},
    core::{Epoch, EthSpec, Hash256, Slot},
    execution::Eth1Data,
    sync_committee::SyncCommittee,
};

/// Mirror of `BeaconState` (Gloas) with every `List`/`ProgressiveList` field replaced by a
/// [`ListSummary`], and every other field left unchanged. Shares the same `hash_tree_root` as the
/// `BeaconStateGloas` it summarizes, since `progressive_container` merkleization (like regular
/// `Container` merkleization) depends only on the ordered sequence of field roots, and a
/// `ListSummary` built from a list's real `items_root`/`num_items` reproduces that list's root
/// exactly.
///
/// Only targets Gloas: checkpoint sync only ever needs a recent finalized state, and Gloas is
/// already the live/rolling-out fork (`plataberget`, then `hoodi`/`sepolia`, then mainnet).
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash)]
#[serde(bound = "E: EthSpec", deny_unknown_fields)]
#[cfg_attr(feature = "arbitrary", arbitrary(bound = "E: EthSpec"))]
#[tree_hash(
    struct_behaviour = "progressive_container",
    active_fields(
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
    )
)]
pub struct BeaconStateSummary<E: EthSpec> {
    // Versioning
    pub genesis_time: u64,
    pub genesis_validators_root: Hash256,
    pub slot: Slot,
    pub fork: Fork,

    // History
    pub latest_block_header: BeaconBlockHeader,
    pub block_roots: FixedVector<Hash256, E::SlotsPerHistoricalRoot>,
    pub state_roots: FixedVector<Hash256, E::SlotsPerHistoricalRoot>,
    pub historical_roots: ListSummary,

    // Ethereum 1.0 chain data
    pub eth1_data: Eth1Data,
    pub eth1_data_votes: ListSummary,
    #[serde(with = "serde_utils::quoted_u64")]
    pub eth1_deposit_index: u64,

    // Registry
    pub validators: ListSummary,
    pub balances: ListSummary,

    // Randomness
    pub randao_mixes: FixedVector<Hash256, E::EpochsPerHistoricalVector>,

    // Slashings
    #[serde(with = "ssz_types::serde_utils::quoted_u64_fixed_vec")]
    pub slashings: FixedVector<u64, E::EpochsPerSlashingsVector>,

    // Participation (Gloas uses ProgressiveList, summarized like any other list)
    pub previous_epoch_participation: ListSummary,
    pub current_epoch_participation: ListSummary,

    // Finality
    pub justification_bits: BitVector<E::JustificationBitsLength>,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,

    // Inactivity
    pub inactivity_scores: ListSummary,

    // Light-client sync committees
    pub current_sync_committee: Arc<SyncCommittee<E>>,
    pub next_sync_committee: Arc<SyncCommittee<E>>,

    // Execution
    pub latest_block_hash: ExecutionBlockHash,
    #[serde(with = "serde_utils::quoted_u64")]
    pub next_withdrawal_index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub next_withdrawal_validator_index: u64,
    pub historical_summaries: ListSummary,

    // Electra
    #[serde(with = "serde_utils::quoted_u64")]
    pub deposit_requests_start_index: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub deposit_balance_to_consume: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    pub exit_balance_to_consume: u64,
    pub earliest_exit_epoch: Epoch,
    #[serde(with = "serde_utils::quoted_u64")]
    pub consolidation_balance_to_consume: u64,
    pub earliest_consolidation_epoch: Epoch,
    pub pending_deposits: ListSummary,
    pub pending_partial_withdrawals: ListSummary,
    pub pending_consolidations: ListSummary,

    // Fulu
    #[serde(with = "ssz_types::serde_utils::quoted_u64_fixed_vec")]
    pub proposer_lookahead: FixedVector<u64, E::ProposerLookaheadSlots>,

    // Gloas
    pub builders: ListSummary,
    #[serde(with = "serde_utils::quoted_u64")]
    pub next_withdrawal_builder_index: BuilderIndex,
    pub execution_payload_availability: BitVector<E::SlotsPerHistoricalRoot>,
    pub builder_pending_payments:
        FixedVector<BuilderPendingPayment, E::BuilderPendingPaymentsLimit>,
    pub builder_pending_withdrawals: ListSummary,
    pub latest_execution_payload_bid: ExecutionPayloadBid<E>,
    pub payload_expected_withdrawals: ListSummary,
    pub ptc_window: FixedVector<FixedVector<u64, E::PTCSize>, E::PtcWindowLength>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MinimalEthSpec;

    ssz_and_tree_hash_tests!(BeaconStateSummary<MinimalEthSpec>);
}
