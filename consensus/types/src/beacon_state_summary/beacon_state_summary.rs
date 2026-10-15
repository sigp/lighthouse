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
    use crate::{BeaconStateGloas, MinimalEthSpec, test_utils::test_arbitrary_instance};
    use tree_hash::{MerkleHasher, ProgressiveMerkleHasher, TreeHash, TreeHashType};
    use typenum::Unsigned;

    ssz_and_tree_hash_tests!(BeaconStateSummary<MinimalEthSpec>);

    /// Merkleizes `items` to a regular (non-progressive) `List`'s items_root, matching the SSZ
    /// spec's `merkleize(pack(items), limit=chunk_count(type))` exactly, using only public
    /// `tree_hash` primitives (not milhouse's still-private tree access).
    fn regular_items_root<T: TreeHash>(items: &[T], capacity: usize) -> Hash256 {
        let leaves = match T::tree_hash_type() {
            TreeHashType::Basic => capacity.div_ceil(T::tree_hash_packing_factor()),
            TreeHashType::Container | TreeHashType::List | TreeHashType::Vector => capacity,
        };
        let mut hasher = MerkleHasher::with_leaves(leaves);
        match T::tree_hash_type() {
            TreeHashType::Basic => {
                for item in items {
                    hasher
                        .write(&item.tree_hash_packed_encoding())
                        .expect("capacity is large enough for all items");
                }
            }
            _ => {
                for item in items {
                    hasher
                        .write(item.tree_hash_root().as_slice())
                        .expect("capacity is large enough for all items");
                }
            }
        }
        hasher.finish().expect("no partial buffer remains")
    }

    /// Same as `regular_items_root`, but for `ProgressiveList` fields (EIP-7916 merkleization,
    /// no fixed capacity).
    fn progressive_items_root<T: TreeHash>(items: &[T]) -> Hash256 {
        let mut hasher = ProgressiveMerkleHasher::new();
        match T::tree_hash_type() {
            TreeHashType::Basic => {
                for item in items {
                    hasher
                        .write(&item.tree_hash_packed_encoding())
                        .expect("progressive hasher accepts any number of chunks");
                }
            }
            _ => {
                for item in items {
                    hasher
                        .write(item.tree_hash_root().as_slice())
                        .expect("progressive hasher accepts any number of chunks");
                }
            }
        }
        hasher.finish().expect("no partial buffer remains")
    }

    fn list_summary_regular<T: TreeHash>(items: &[T], capacity: usize) -> ListSummary {
        ListSummary {
            items_root: regular_items_root(items, capacity),
            num_items: items.len() as u64,
        }
    }

    fn list_summary_progressive<T: TreeHash>(items: &[T]) -> ListSummary {
        ListSummary {
            items_root: progressive_items_root(items),
            num_items: items.len() as u64,
        }
    }

    /// Proves `BeaconStateSummary::tree_hash_root()` equals the real `BeaconStateGloas` it
    /// summarizes, end to end, on a randomly generated (but structurally valid) state. This is
    /// the concrete verification of the equivalence argument the whole design rests on, built
    /// without needing milhouse's still-missing public items_root accessor: item values are read
    /// out via milhouse's existing public `to_vec()`, and their roots are recomputed
    /// independently using only public `tree_hash` primitives.
    #[test]
    fn summary_root_matches_real_gloas_state() {
        let state: BeaconStateGloas<MinimalEthSpec> = test_arbitrary_instance();

        let historical_roots_limit =
            <MinimalEthSpec as EthSpec>::HistoricalRootsLimit::to_usize();
        let eth1_voting_period =
            <MinimalEthSpec as EthSpec>::SlotsPerEth1VotingPeriod::to_usize();

        let summary = BeaconStateSummary::<MinimalEthSpec> {
            genesis_time: state.genesis_time,
            genesis_validators_root: state.genesis_validators_root,
            slot: state.slot,
            fork: state.fork,
            latest_block_header: state.latest_block_header.clone(),
            block_roots: FixedVector::new(state.block_roots.to_vec()).unwrap(),
            state_roots: FixedVector::new(state.state_roots.to_vec()).unwrap(),
            historical_roots: list_summary_regular(
                &state.historical_roots.to_vec(),
                historical_roots_limit,
            ),
            eth1_data: state.eth1_data.clone(),
            eth1_data_votes: list_summary_regular(
                &state.eth1_data_votes.to_vec(),
                eth1_voting_period,
            ),
            eth1_deposit_index: state.eth1_deposit_index,
            validators: list_summary_progressive(&state.validators.to_vec()),
            balances: list_summary_progressive(&state.balances.to_vec()),
            randao_mixes: FixedVector::new(state.randao_mixes.to_vec()).unwrap(),
            slashings: FixedVector::new(state.slashings.to_vec()).unwrap(),
            previous_epoch_participation: list_summary_progressive(
                &state.previous_epoch_participation.to_vec(),
            ),
            current_epoch_participation: list_summary_progressive(
                &state.current_epoch_participation.to_vec(),
            ),
            justification_bits: state.justification_bits.clone(),
            previous_justified_checkpoint: state.previous_justified_checkpoint,
            current_justified_checkpoint: state.current_justified_checkpoint,
            finalized_checkpoint: state.finalized_checkpoint,
            inactivity_scores: list_summary_progressive(&state.inactivity_scores.to_vec()),
            current_sync_committee: state.current_sync_committee.clone(),
            next_sync_committee: state.next_sync_committee.clone(),
            latest_block_hash: state.latest_block_hash,
            next_withdrawal_index: state.next_withdrawal_index,
            next_withdrawal_validator_index: state.next_withdrawal_validator_index,
            historical_summaries: list_summary_regular(
                &state.historical_summaries.to_vec(),
                historical_roots_limit,
            ),
            deposit_requests_start_index: state.deposit_requests_start_index,
            deposit_balance_to_consume: state.deposit_balance_to_consume,
            exit_balance_to_consume: state.exit_balance_to_consume,
            earliest_exit_epoch: state.earliest_exit_epoch,
            consolidation_balance_to_consume: state.consolidation_balance_to_consume,
            earliest_consolidation_epoch: state.earliest_consolidation_epoch,
            pending_deposits: list_summary_progressive(&state.pending_deposits.to_vec()),
            pending_partial_withdrawals: list_summary_progressive(
                &state.pending_partial_withdrawals.to_vec(),
            ),
            pending_consolidations: list_summary_progressive(
                &state.pending_consolidations.to_vec(),
            ),
            proposer_lookahead: FixedVector::new(state.proposer_lookahead.to_vec()).unwrap(),
            builders: list_summary_progressive(&state.builders.to_vec()),
            next_withdrawal_builder_index: state.next_withdrawal_builder_index,
            execution_payload_availability: state.execution_payload_availability.clone(),
            builder_pending_payments: FixedVector::new(state.builder_pending_payments.to_vec())
                .unwrap(),
            builder_pending_withdrawals: list_summary_progressive(
                &state.builder_pending_withdrawals.to_vec(),
            ),
            latest_execution_payload_bid: state.latest_execution_payload_bid.clone(),
            payload_expected_withdrawals: list_summary_progressive(
                &state.payload_expected_withdrawals.to_vec(),
            ),
            ptc_window: FixedVector::new(state.ptc_window.to_vec()).unwrap(),
        };

        assert_eq!(
            summary.tree_hash_root(),
            state.tree_hash_root(),
            "BeaconStateSummary must reproduce the real BeaconStateGloas's hash_tree_root"
        );
    }
}
