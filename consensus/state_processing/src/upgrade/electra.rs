use bls::Signature;
use itertools::Itertools;
use safe_arith::SafeArith;
use std::mem;
use types::{
    BeaconState, BeaconStateElectra, BeaconStateError as Error, ChainSpec, Epoch, EpochCache,
    EthSpec, Fork, PendingDeposit,
};

/// Transform a `Deneb` state into an `Electra` state.
pub fn upgrade_to_electra<E: EthSpec>(
    pre_state: &mut BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let epoch = pre_state.current_epoch();

    let activation_exit_epoch = spec.compute_activation_exit_epoch(epoch)?;
    let earliest_exit_epoch = pre_state
        .validators()
        .iter()
        .filter(|v| v.exit_epoch != spec.far_future_epoch)
        .map(|v| v.exit_epoch)
        .max()
        .unwrap_or(activation_exit_epoch)
        .max(activation_exit_epoch)
        .safe_add(1)?;

    // The total active balance cache must be built before the consolidation churn limit
    // is calculated.
    pre_state.build_total_active_balance_cache(spec)?;
    let earliest_consolidation_epoch = spec.compute_activation_exit_epoch(epoch)?;

    let mut post = upgrade_state_to_electra(
        pre_state,
        earliest_exit_epoch,
        earliest_consolidation_epoch,
        spec,
    )?;

    *post.exit_balance_to_consume_mut()? = post.get_activation_exit_churn_limit(spec)?;
    *post.consolidation_balance_to_consume_mut()? = post.get_consolidation_churn_limit(spec)?;

    // Add validators that are not yet active to pending balance deposits
    let validators = post.validators().clone();
    let pre_activation = validators
        .iter()
        .enumerate()
        .filter(|(_, validator)| validator.activation_epoch == spec.far_future_epoch)
        .sorted_by_key(|(index, validator)| (validator.activation_eligibility_epoch, *index))
        .collect::<Vec<_>>();

    // Process validators to queue entire balance and reset them
    for (index, _) in pre_activation {
        let balance = post
            .balances_mut()
            .get_mut(index)
            .ok_or(Error::UnknownValidator(index))?;
        let balance_copy = *balance;
        *balance = 0_u64;

        let validator = post
            .validators_mut()
            .get_mut(index)
            .ok_or(Error::UnknownValidator(index))?;
        validator.effective_balance = 0;
        validator.activation_eligibility_epoch = spec.far_future_epoch;
        let pubkey = validator.pubkey;
        let withdrawal_credentials = validator.withdrawal_credentials;

        post.pending_deposits_mut()?
            .push(PendingDeposit {
                pubkey,
                withdrawal_credentials,
                amount: balance_copy,
                signature: Signature::infinity()?.into(),
                slot: spec.genesis_slot,
            })
            .map_err(Error::MilhouseError)?;
    }

    // Ensure early adopters of compounding credentials go through the activation churn
    let validators = post.validators().clone();
    for (index, validator) in validators.iter().enumerate() {
        if validator.has_compounding_withdrawal_credential(spec) {
            post.queue_excess_active_balance(index, spec)?;
        }
    }

    *pre_state = post;

    Ok(())
}

pub fn upgrade_state_to_electra<E: EthSpec>(
    pre_state: &mut BeaconState<E>,
    earliest_exit_epoch: Epoch,
    earliest_consolidation_epoch: Epoch,
    spec: &ChainSpec,
) -> Result<BeaconState<E>, Error> {
    let epoch = pre_state.current_epoch();
    let pre = pre_state.as_deneb_mut()?;
    // Where possible, use something like `mem::take` to move fields from behind the &mut
    // reference. For other fields that don't have a good default value, use `clone`.
    //
    // Fixed size vectors get cloned because replacing them would require the same size
    // allocation as cloning.
    let post = BeaconState::Electra(BeaconStateElectra {
        // Versioning
        genesis_time: pre.genesis_time,
        genesis_validators_root: pre.genesis_validators_root,
        slot: pre.slot,
        fork: Fork {
            previous_version: pre.fork.current_version,
            current_version: spec.electra_fork_version,
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
        // Execution
        latest_execution_payload_header: pre.latest_execution_payload_header.upgrade_to_electra(),
        // Capella
        next_withdrawal_index: pre.next_withdrawal_index,
        next_withdrawal_validator_index: pre.next_withdrawal_validator_index,
        historical_summaries: pre.historical_summaries.clone(),
        // Electra
        deposit_requests_start_index: spec.unset_deposit_requests_start_index,
        deposit_balance_to_consume: 0,
        exit_balance_to_consume: 0,
        earliest_exit_epoch,
        consolidation_balance_to_consume: 0,
        earliest_consolidation_epoch,
        pending_deposits: Default::default(),
        pending_partial_withdrawals: Default::default(),
        pending_consolidations: Default::default(),
        // Caches
        total_active_balance: pre.total_active_balance,
        progressive_balances_cache: mem::take(&mut pre.progressive_balances_cache),
        committee_caches: mem::take(&mut pre.committee_caches),
        pubkey_cache: mem::take(&mut pre.pubkey_cache),
        exit_cache: mem::take(&mut pre.exit_cache),
        slashings_cache: mem::take(&mut pre.slashings_cache),
        epoch_cache: EpochCache::default(),
    });
    Ok(post)
}
