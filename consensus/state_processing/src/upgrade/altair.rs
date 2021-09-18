use crate::common::{get_attestation_participation_flag_indices, get_attesting_indices};
use std::mem;
use std::sync::Arc;
use types::{
    BeaconState, BeaconStateAltair, BeaconStateError as Error, ChainSpec, EthSpec, Fork,
    ParticipationFlags, PendingAttestation, RelativeEpoch, SyncCommittee, VariableList,
};

/// Translate the participation information from the epoch prior to the fork into Altair's format.
pub fn translate_participation<E: EthSpec>(
    state: &mut BeaconState<E>,
    pending_attestations: &VariableList<PendingAttestation<E>, E::MaxPendingAttestations>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    // Previous epoch committee cache is required for `get_attesting_indices`.
    state.build_committee_cache(RelativeEpoch::Previous, spec)?;

    for attestation in pending_attestations {
        let data = &attestation.data;
        let inclusion_delay = attestation.inclusion_delay;

        // Translate attestation inclusion info to flag indices.
        let participation_flag_indices =
            get_attestation_participation_flag_indices(state, data, inclusion_delay, spec)?;

        // Apply flags to all attesting validators.
        let committee = state.get_beacon_committee(data.slot, data.index)?;
        let attesting_indices =
            get_attesting_indices::<E>(committee.committee, &attestation.aggregation_bits)?;
        let epoch_participation = state.previous_epoch_participation_mut()?;

        for index in attesting_indices {
            for flag_index in &participation_flag_indices {
                epoch_participation
                    .get_mut(index)
                    .ok_or(Error::UnknownValidator(index))?
                    .add_flag(*flag_index)?;
            }
        }
    }
    Ok(())
}

/// Transform a `Base` state into an `Altair` state.
pub fn upgrade_to_altair<E: EthSpec>(
    pre_state: &mut BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let epoch = pre_state.current_epoch();
    let pre = pre_state.as_base_mut()?;

    let default_epoch_participation =
        VariableList::new(vec![ParticipationFlags::default(); pre.validators.len()])?;
    let inactivity_scores = VariableList::new(vec![0; pre.validators.len()])?;

    let temp_sync_committee = Arc::new(SyncCommittee::temporary()?);

    // Where possible, use something like `mem::take` to move fields from behind the &mut
    // reference. For other fields that don't have a good default value, use `clone`.
    //
    // Fixed size vectors get cloned because replacing them would require the same size
    // allocation as cloning.
    let mut post = BeaconState::Altair(BeaconStateAltair {
        // Versioning
        genesis_time: pre.genesis_time,
        genesis_validators_root: pre.genesis_validators_root,
        slot: pre.slot,
        fork: Fork {
            previous_version: pre.fork.current_version,
            current_version: spec.altair_fork_version,
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
        previous_epoch_participation: default_epoch_participation.clone(),
        current_epoch_participation: default_epoch_participation,
        // Finality
        justification_bits: pre.justification_bits.clone(),
        previous_justified_checkpoint: pre.previous_justified_checkpoint,
        current_justified_checkpoint: pre.current_justified_checkpoint,
        finalized_checkpoint: pre.finalized_checkpoint,
        // Inactivity
        inactivity_scores,
        // Sync committees
        current_sync_committee: temp_sync_committee.clone(), // not read
        next_sync_committee: temp_sync_committee,            // not read
        // Caches
        total_active_balance: pre.total_active_balance,
        committee_caches: mem::take(&mut pre.committee_caches),
        pubkey_cache: mem::take(&mut pre.pubkey_cache),
        exit_cache: mem::take(&mut pre.exit_cache),
        tree_hash_cache: mem::take(&mut pre.tree_hash_cache),
    });

    // Fill in previous epoch participation from the pre state's pending attestations.
    translate_participation(&mut post, &pre.previous_epoch_attestations, spec)?;

    // Fill in sync committees
    // Note: A duplicate committee is assigned for the current and next committee at the fork
    // boundary
    let sync_committee = Arc::new(post.get_next_sync_committee(spec)?);
    *post.current_sync_committee_mut()? = sync_committee.clone();
    *post.next_sync_committee_mut()? = sync_committee;

    *pre_state = post;

    Ok(())
}
