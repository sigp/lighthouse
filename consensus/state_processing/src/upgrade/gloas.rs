use crate::per_block_processing::{
    is_valid_deposit_signature, process_operations::apply_deposit_for_builder,
};
use milhouse::{List, Vector};
use safe_arith::SafeArith;
use ssz_types::BitVector;
use ssz_types::FixedVector;
use std::collections::HashSet;
use std::mem;
use typenum::Unsigned;
use types::{
    BeaconState, BeaconStateError as Error, BeaconStateGloas, BuilderPendingPayment, ChainSpec,
    DepositData, EthSpec, ExecutionPayloadBid, Fork, is_builder_withdrawal_credential,
};

/// Transform a `Fulu` state into a `Gloas` state.
pub fn upgrade_to_gloas<E: EthSpec>(
    pre_state: &mut BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let post = upgrade_state_to_gloas(pre_state, spec)?;

    *pre_state = post;

    Ok(())
}

pub fn upgrade_state_to_gloas<E: EthSpec>(
    pre_state: &mut BeaconState<E>,
    spec: &ChainSpec,
) -> Result<BeaconState<E>, Error> {
    let epoch = pre_state.current_epoch();
    let pre = pre_state.as_fulu_mut()?;
    // Where possible, use something like `mem::take` to move fields from behind the &mut
    // reference. For other fields that don't have a good default value, use `clone`.
    //
    // Fixed size vectors get cloned because replacing them would require the same size
    // allocation as cloning.
    let mut post = BeaconState::Gloas(BeaconStateGloas {
        // Versioning
        genesis_time: pre.genesis_time,
        genesis_validators_root: pre.genesis_validators_root,
        slot: pre.slot,
        fork: Fork {
            previous_version: pre.fork.current_version,
            current_version: spec.gloas_fork_version,
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
        // `Participation
        previous_epoch_participation: mem::take(&mut pre.previous_epoch_participation),
        current_epoch_participation: mem::take(&mut pre.current_epoch_participation),
        // Finality
        justification_bits: pre.justification_bits.clone(),
        previous_justified_checkpoint: pre.previous_justified_checkpoint,
        current_justified_checkpoint: pre.current_justified_checkpoint,
        finalized_checkpoint: pre.finalized_checkpoint,
        // Inactivity
        inactivity_scores: mem::take(&mut pre.inactivity_scores),
        // Sync committees
        current_sync_committee: pre.current_sync_committee.clone(),
        next_sync_committee: pre.next_sync_committee.clone(),
        // Execution Bid
        latest_execution_payload_bid: ExecutionPayloadBid {
            block_hash: pre.latest_execution_payload_header.block_hash,
            ..Default::default()
        },
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
        builders: List::default(),
        next_withdrawal_builder_index: 0,
        // All bits set to true per spec:
        // execution_payload_availability = [0b1 for _ in range(SLOTS_PER_HISTORICAL_ROOT)]
        execution_payload_availability: BitVector::from_bytes(
            vec![0xFFu8; E::SlotsPerHistoricalRoot::to_usize() / 8].into(),
        )
        .map_err(|_| Error::InvalidBitfield)?,
        builder_pending_payments: Vector::from_elem(BuilderPendingPayment::default())?,
        builder_pending_withdrawals: List::default(), // Empty list initially,
        latest_block_hash: pre.latest_execution_payload_header.block_hash,
        payload_expected_withdrawals: List::default(),
        ptc_window: Vector::from_elem(FixedVector::from_elem(0))?, // placeholder, will be initialized below
        // Caches
        total_active_balance: pre.total_active_balance,
        progressive_balances_cache: mem::take(&mut pre.progressive_balances_cache),
        committee_caches: mem::take(&mut pre.committee_caches),
        pubkey_cache: mem::take(&mut pre.pubkey_cache),
        exit_cache: mem::take(&mut pre.exit_cache),
        slashings_cache: mem::take(&mut pre.slashings_cache),
        epoch_cache: mem::take(&mut pre.epoch_cache),
    });
    // [New in Gloas:EIP7732]
    onboard_builders_from_pending_deposits(&mut post, spec)?;
    initialize_ptc_window(&mut post, spec)?;

    Ok(post)
}

/// Initialize the `ptc_window` field in the beacon state at fork transition.
///
/// The window contains:
/// - One epoch of empty entries (previous epoch)
/// - Computed PTC for the current epoch through `1 + MIN_SEED_LOOKAHEAD` epochs
fn initialize_ptc_window<E: EthSpec>(
    state: &mut BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let slots_per_epoch = E::slots_per_epoch() as usize;

    let empty_previous_epoch = vec![FixedVector::<u64, E::PTCSize>::from_elem(0); slots_per_epoch];
    let mut ptcs = empty_previous_epoch;

    // Compute PTC for current epoch + lookahead epochs
    let current_epoch = state.current_epoch();
    for e in 0..=spec.min_seed_lookahead.as_u64() {
        let epoch = current_epoch.safe_add(e)?;
        let committee_cache = state.initialize_committee_cache_for_lookahead(epoch, spec)?;
        let start_slot = epoch.start_slot(E::slots_per_epoch());
        for i in 0..slots_per_epoch {
            let slot = start_slot.safe_add(i as u64)?;
            let ptc = state.compute_ptc_with_cache(slot, &committee_cache, spec)?;
            let ptc_u64: Vec<u64> = ptc.into_iter().map(|v| v as u64).collect();
            let entry = FixedVector::new(ptc_u64)?;
            ptcs.push(entry);
        }
    }

    *state.ptc_window_mut()? = Vector::new(ptcs)?;

    Ok(())
}

/// Applies any pending deposit for builders, effectively onboarding builders at the fork.
fn onboard_builders_from_pending_deposits<E: EthSpec>(
    state: &mut BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    // Rather than tracking all `validator_pubkeys` in one place as the spec does, we keep a
    // hashset for *just* the new validator pubkeys, and use the state's efficient
    // `get_validator_index` function instead of an O(n) iteration over the full validator list.
    let mut new_validator_pubkeys = HashSet::new();

    // Clone pending deposits to avoid borrow conflicts when mutating state.
    let current_pending_deposits = state.pending_deposits()?.clone();

    let mut pending_deposits = List::empty();

    for deposit in &current_pending_deposits {
        // Deposits for existing validators stay in the pending queue.
        if new_validator_pubkeys.contains(&deposit.pubkey)
            || state.get_validator_index(&deposit.pubkey)?.is_some()
        {
            pending_deposits.push(deposit.clone())?;
            continue;
        }

        // Re-scan builder list each iteration because `apply_deposit_for_builder` may add
        // new builders to the registry.
        // TODO(gloas): this linear scan could be optimized, see:
        // https://github.com/sigp/lighthouse/issues/8783
        let builder_index = state
            .builders()?
            .iter()
            .position(|b| b.pubkey == deposit.pubkey);

        let has_builder_credentials =
            is_builder_withdrawal_credential(deposit.withdrawal_credentials, spec);

        if builder_index.is_some() || has_builder_credentials {
            let builder_index_opt = builder_index.map(|i| i as u64);
            apply_deposit_for_builder(
                state,
                builder_index_opt,
                deposit.pubkey,
                deposit.withdrawal_credentials,
                deposit.amount,
                deposit.signature.clone(),
                deposit.slot,
                spec,
            )?;
            continue;
        }

        // If there is a pending deposit for a new validator that has a valid signature,
        // track the pubkey so that subsequent builder deposits for the same pubkey stay
        // in pending (applied to the validator later) rather than creating a builder.
        // Deposits with invalid signatures are dropped since they would fail in
        // apply_pending_deposit anyway.
        let deposit_data = DepositData {
            pubkey: deposit.pubkey,
            withdrawal_credentials: deposit.withdrawal_credentials,
            amount: deposit.amount,
            signature: deposit.signature.clone(),
        };
        if is_valid_deposit_signature(&deposit_data, spec).is_ok() {
            new_validator_pubkeys.insert(deposit.pubkey);
            pending_deposits.push(deposit.clone())?;
        }
    }

    *state.pending_deposits_mut()? = pending_deposits;

    Ok(())
}
