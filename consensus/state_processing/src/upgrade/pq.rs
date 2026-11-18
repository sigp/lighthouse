use milhouse::{ProgressiveList, Vector};
use std::mem;
use types::{
    AggregationCommittees, BeaconState, BeaconStateError as Error, BeaconStatePq, ChainSpec,
    EthSpec, Fork,
};

/// Transform a `Gloas` state into a `Pq` state.
///
/// This produces a structurally valid `Pq` state, not the spec's `upgrade_to_pq`: the fields
/// that Pq removes are dropped and the fields it adds are empty. It does not yet re-key
/// validators and builders with their registered XMSS keys, exit the unregistered ones, or
/// compute the aggregation committee window.
pub fn upgrade_to_pq<E: EthSpec>(
    pre_state: &mut BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let post = upgrade_state_to_pq(pre_state, spec)?;

    *pre_state = post;

    Ok(())
}

pub fn upgrade_state_to_pq<E: EthSpec>(
    pre_state: &mut BeaconState<E>,
    spec: &ChainSpec,
) -> Result<BeaconState<E>, Error> {
    let epoch = pre_state.current_epoch();
    let pre = pre_state.as_gloas_mut()?;
    // Where possible, use something like `mem::take` to move fields from behind the &mut
    // reference. For other fields that don't have a good default value, use `clone`.
    //
    // Fixed size vectors get cloned because replacing them would require the same size
    // allocation as cloning.
    let post = BeaconState::Pq(BeaconStatePq {
        // Versioning
        genesis_time: pre.genesis_time,
        genesis_validators_root: pre.genesis_validators_root,
        slot: pre.slot,
        fork: Fork {
            previous_version: pre.fork.current_version,
            current_version: spec.pq_fork_version,
            epoch,
        },
        // History
        latest_block_header: pre.latest_block_header.clone(),
        block_roots: pre.block_roots.clone(),
        state_roots: pre.state_roots.clone(),
        historical_roots: mem::take(&mut pre.historical_roots),
        // Eth1
        eth1_data: pre.eth1_data.clone(),
        eth1_data_votes: mem::take(&mut pre.eth1_data_votes),
        eth1_deposit_index: pre.eth1_deposit_index,
        // Registry
        validators: mem::take(&mut pre.validators),
        balances: mem::take(&mut pre.balances),
        // Randomness
        randao_mixes: pre.randao_mixes.clone(),
        // Slashings
        slashings: pre.slashings.clone(),
        // Participation
        previous_epoch_participation: mem::take(&mut pre.previous_epoch_participation),
        current_epoch_participation: mem::take(&mut pre.current_epoch_participation),
        // Finality
        justification_bits: pre.justification_bits.clone(),
        previous_justified_checkpoint: pre.previous_justified_checkpoint,
        current_justified_checkpoint: pre.current_justified_checkpoint,
        finalized_checkpoint: pre.finalized_checkpoint,
        // Inactivity
        inactivity_scores: mem::take(&mut pre.inactivity_scores),
        // [Modified in Pq] The sync committees are removed.
        // Execution Bid
        latest_execution_payload_bid: pre.latest_execution_payload_bid.clone(),
        // Capella
        next_withdrawal_index: pre.next_withdrawal_index,
        next_withdrawal_validator_index: pre.next_withdrawal_validator_index,
        historical_summaries: pre.historical_summaries.clone(),
        // Electra
        deposit_requests_start_index: pre.deposit_requests_start_index,
        deposit_balance_to_consume: pre.deposit_balance_to_consume,
        exit_balance_to_consume: pre.exit_balance_to_consume,
        earliest_exit_epoch: pre.earliest_exit_epoch,
        consolidation_balance_to_consume: pre.consolidation_balance_to_consume,
        earliest_consolidation_epoch: pre.earliest_consolidation_epoch,
        pending_deposits: pre.pending_deposits.clone(),
        pending_partial_withdrawals: pre.pending_partial_withdrawals.clone(),
        pending_consolidations: pre.pending_consolidations.clone(),
        proposer_lookahead: mem::take(&mut pre.proposer_lookahead),
        // Gloas
        builders: mem::take(&mut pre.builders),
        next_withdrawal_builder_index: pre.next_withdrawal_builder_index,
        execution_payload_availability: pre.execution_payload_availability.clone(),
        builder_pending_payments: pre.builder_pending_payments.clone(),
        builder_pending_withdrawals: mem::take(&mut pre.builder_pending_withdrawals),
        latest_block_hash: pre.latest_block_hash,
        payload_expected_withdrawals: mem::take(&mut pre.payload_expected_withdrawals),
        ptc_window: pre.ptc_window.clone(),
        // Pq
        validator_preregistrations: ProgressiveList::empty(),
        builder_preregistrations: ProgressiveList::empty(),
        // Every slot of the window holds an empty list of aggregation committees. The spec fills
        // the window with `compute_aggregation_committees` for each epoch it covers.
        aggregation_committee_window: Vector::from_elem(AggregationCommittees::default())?,
        // Caches
        total_active_balance: pre.total_active_balance,
        progressive_balances_cache: mem::take(&mut pre.progressive_balances_cache),
        committee_caches: mem::take(&mut pre.committee_caches),
        pubkey_cache: mem::take(&mut pre.pubkey_cache),
        exit_cache: mem::take(&mut pre.exit_cache),
        slashings_cache: mem::take(&mut pre.slashings_cache),
        epoch_cache: mem::take(&mut pre.epoch_cache),
    });

    Ok(post)
}
