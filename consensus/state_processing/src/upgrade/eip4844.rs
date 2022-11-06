use std::mem;
use types::{BeaconState, BeaconStateEip4844, BeaconStateError as Error, ChainSpec, EthSpec, Fork};

/// Transform a `Capella` state into an `Eip4844` state.
pub fn upgrade_to_eip4844<E: EthSpec>(
    pre_state: &mut BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let epoch = pre_state.current_epoch();
    let pre = pre_state.as_capella_mut()?;

    // FIXME(sean) This is a hack to let us participate in testnets where capella doesn't exist.
    // if we are disabling withdrawals, assume we should fork off of bellatrix.
    let previous_fork_version = if cfg!(feature ="withdrawals") {
        pre.fork.current_version
    } else {
        spec.bellatrix_fork_version
    };

    // Where possible, use something like `mem::take` to move fields from behind the &mut
    // reference. For other fields that don't have a good default value, use `clone`.
    //
    // Fixed size vectors get cloned because replacing them would require the same size
    // allocation as cloning.
    let post = BeaconState::Eip4844(BeaconStateEip4844 {
        // Versioning
        genesis_time: pre.genesis_time,
        genesis_validators_root: pre.genesis_validators_root,
        slot: pre.slot,
        fork: Fork {
            previous_version: previous_fork_version,
            current_version: spec.eip4844_fork_version,
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
        latest_execution_payload_header: pre.latest_execution_payload_header.upgrade_to_eip4844(),
        // Withdrawals
        #[cfg(feature = "withdrawals")]
        withdrawal_queue: mem::take(&mut pre.withdrawal_queue),
        #[cfg(feature = "withdrawals")]
        next_withdrawal_index: pre.next_withdrawal_index,
        #[cfg(feature = "withdrawals")]
        next_partial_withdrawal_validator_index: pre.next_partial_withdrawal_validator_index,
        // Caches
        total_active_balance: pre.total_active_balance,
        committee_caches: mem::take(&mut pre.committee_caches),
        pubkey_cache: mem::take(&mut pre.pubkey_cache),
        exit_cache: mem::take(&mut pre.exit_cache),
        tree_hash_cache: mem::take(&mut pre.tree_hash_cache),
    });

    *pre_state = post;

    Ok(())
}
