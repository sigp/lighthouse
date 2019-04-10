use crate::common::slash_validator;
use errors::{BlockInvalid as Invalid, BlockProcessingError as Error, IntoWithIndex};
use rayon::prelude::*;
use ssz::{SignedRoot, TreeHash};
use types::*;

pub use self::verify_attester_slashing::{
    gather_attester_slashing_indices, gather_attester_slashing_indices_modular,
    verify_attester_slashing,
};
pub use self::verify_proposer_slashing::verify_proposer_slashing;
pub use validate_attestation::{
    validate_attestation, validate_attestation_time_independent_only,
    validate_attestation_without_signature,
};
pub use verify_deposit::{get_existing_validator_index, verify_deposit, verify_deposit_index};
pub use verify_exit::{verify_exit, verify_exit_time_independent_only};
pub use verify_slashable_attestation::verify_slashable_attestation;
pub use verify_transfer::{
    execute_transfer, verify_transfer, verify_transfer_time_independent_only,
};

pub mod errors;
pub mod tests;
pub mod block_processing_builder;
mod validate_attestation;
mod verify_attester_slashing;
mod verify_deposit;
mod verify_exit;
mod verify_proposer_slashing;
mod verify_slashable_attestation;
mod verify_transfer;

// Set to `true` to check the merkle proof that a deposit is in the eth1 deposit root.
//
// Presently disabled to make testing easier.
const VERIFY_DEPOSIT_MERKLE_PROOFS: bool = false;

/// Updates the state for a new block, whilst validating that the block is valid.
///
/// Returns `Ok(())` if the block is valid and the state was successfully updated. Otherwise
/// returns an error describing why the block was invalid or how the function failed to execute.
///
/// Spec v0.5.0
pub fn per_block_processing(
    state: &mut BeaconState,
    block: &BeaconBlock,
    spec: &ChainSpec,
) -> Result<(), Error> {
    per_block_processing_signature_optional(state, block, true, spec)
}

/// Updates the state for a new block, whilst validating that the block is valid, without actually
/// checking the block proposer signature.
///
/// Returns `Ok(())` if the block is valid and the state was successfully updated. Otherwise
/// returns an error describing why the block was invalid or how the function failed to execute.
///
/// Spec v0.5.0
pub fn per_block_processing_without_verifying_block_signature(
    state: &mut BeaconState,
    block: &BeaconBlock,
    spec: &ChainSpec,
) -> Result<(), Error> {
    per_block_processing_signature_optional(state, block, false, spec)
}

/// Updates the state for a new block, whilst validating that the block is valid, optionally
/// checking the block proposer signature.
///
/// Returns `Ok(())` if the block is valid and the state was successfully updated. Otherwise
/// returns an error describing why the block was invalid or how the function failed to execute.
///
/// Spec v0.5.0
fn per_block_processing_signature_optional(
    mut state: &mut BeaconState,
    block: &BeaconBlock,
    should_verify_block_signature: bool,
    spec: &ChainSpec,
) -> Result<(), Error> {
    process_block_header(state, block, spec)?;

    // Ensure the current and previous epoch cache is built.
    state.build_epoch_cache(RelativeEpoch::Previous, spec)?;
    state.build_epoch_cache(RelativeEpoch::Current, spec)?;

    if should_verify_block_signature {
        verify_block_signature(&state, &block, &spec)?;
    }
    process_randao(&mut state, &block, &spec)?;
    process_eth1_data(&mut state, &block.body.eth1_data)?;
    process_proposer_slashings(&mut state, &block.body.proposer_slashings, spec)?;
    process_attester_slashings(&mut state, &block.body.attester_slashings, spec)?;
    process_attestations(&mut state, &block.body.attestations, spec)?;
    process_deposits(&mut state, &block.body.deposits, spec)?;
    process_exits(&mut state, &block.body.voluntary_exits, spec)?;
    process_transfers(&mut state, &block.body.transfers, spec)?;

    Ok(())
}

/// Processes the block header.
///
/// Spec v0.5.0
pub fn process_block_header(
    state: &mut BeaconState,
    block: &BeaconBlock,
    spec: &ChainSpec,
) -> Result<(), Error> {
    verify!(block.slot == state.slot, Invalid::StateSlotMismatch);

    // NOTE: this is not to spec. I think spec is broken. See:
    //
    // https://github.com/ethereum/eth2.0-specs/issues/797
    verify!(
        block.previous_block_root == *state.get_block_root(state.slot - 1, spec)?,
        Invalid::ParentBlockRootMismatch
    );

    state.latest_block_header = block.temporary_block_header(spec);

    Ok(())
}

/// Verifies the signature of a block.
///
/// Spec v0.5.0
pub fn verify_block_signature(
    state: &BeaconState,
    block: &BeaconBlock,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let block_proposer = &state.validator_registry
        [state.get_beacon_proposer_index(block.slot, RelativeEpoch::Current, spec)?];

    let domain = spec.get_domain(
        block.slot.epoch(spec.slots_per_epoch),
        Domain::BeaconBlock,
        &state.fork,
    );

    verify!(
        block
            .signature
            .verify(&block.signed_root()[..], domain, &block_proposer.pubkey),
        Invalid::BadSignature
    );

    Ok(())
}

/// Verifies the `randao_reveal` against the block's proposer pubkey and updates
/// `state.latest_randao_mixes`.
///
/// Spec v0.5.0
pub fn process_randao(
    state: &mut BeaconState,
    block: &BeaconBlock,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let block_proposer = &state.validator_registry
        [state.get_beacon_proposer_index(block.slot, RelativeEpoch::Current, spec)?];

    // Verify the RANDAO is a valid signature of the proposer.
    verify!(
        block.body.randao_reveal.verify(
            &state.current_epoch(spec).hash_tree_root()[..],
            spec.get_domain(
                block.slot.epoch(spec.slots_per_epoch),
                Domain::Randao,
                &state.fork
            ),
            &block_proposer.pubkey
        ),
        Invalid::BadRandaoSignature
    );

    // Update the current epoch RANDAO mix.
    state.update_randao_mix(state.current_epoch(spec), &block.body.randao_reveal, spec)?;

    Ok(())
}

/// Update the `state.eth1_data_votes` based upon the `eth1_data` provided.
///
/// Spec v0.5.0
pub fn process_eth1_data(state: &mut BeaconState, eth1_data: &Eth1Data) -> Result<(), Error> {
    // Attempt to find a `Eth1DataVote` with matching `Eth1Data`.
    let matching_eth1_vote_index = state
        .eth1_data_votes
        .iter()
        .position(|vote| vote.eth1_data == *eth1_data);

    // If a vote exists, increment it's `vote_count`. Otherwise, create a new `Eth1DataVote`.
    if let Some(index) = matching_eth1_vote_index {
        state.eth1_data_votes[index].vote_count += 1;
    } else {
        state.eth1_data_votes.push(Eth1DataVote {
            eth1_data: eth1_data.clone(),
            vote_count: 1,
        });
    }

    Ok(())
}

/// Validates each `ProposerSlashing` and updates the state, short-circuiting on an invalid object.
///
/// Returns `Ok(())` if the validation and state updates completed successfully, otherwise returns
/// an `Err` describing the invalid object or cause of failure.
///
/// Spec v0.5.0
pub fn process_proposer_slashings(
    state: &mut BeaconState,
    proposer_slashings: &[ProposerSlashing],
    spec: &ChainSpec,
) -> Result<(), Error> {
    verify!(
        proposer_slashings.len() as u64 <= spec.max_proposer_slashings,
        Invalid::MaxProposerSlashingsExceeded
    );

    // Verify proposer slashings in parallel.
    proposer_slashings
        .par_iter()
        .enumerate()
        .try_for_each(|(i, proposer_slashing)| {
            verify_proposer_slashing(proposer_slashing, &state, spec)
                .map_err(|e| e.into_with_index(i))
        })?;

    // Update the state.
    for proposer_slashing in proposer_slashings {
        slash_validator(state, proposer_slashing.proposer_index as usize, spec)?;
    }

    Ok(())
}

/// Validates each `AttesterSlsashing` and updates the state, short-circuiting on an invalid object.
///
/// Returns `Ok(())` if the validation and state updates completed successfully, otherwise returns
/// an `Err` describing the invalid object or cause of failure.
///
/// Spec v0.5.0
pub fn process_attester_slashings(
    state: &mut BeaconState,
    attester_slashings: &[AttesterSlashing],
    spec: &ChainSpec,
) -> Result<(), Error> {
    verify!(
        attester_slashings.len() as u64 <= spec.max_attester_slashings,
        Invalid::MaxAttesterSlashingsExceed
    );

    // Verify the `SlashableAttestation`s in parallel (these are the resource-consuming objects, not
    // the `AttesterSlashing`s themselves).
    let mut slashable_attestations: Vec<&SlashableAttestation> =
        Vec::with_capacity(attester_slashings.len() * 2);
    for attester_slashing in attester_slashings {
        slashable_attestations.push(&attester_slashing.slashable_attestation_1);
        slashable_attestations.push(&attester_slashing.slashable_attestation_2);
    }

    // Verify slashable attestations in parallel.
    slashable_attestations
        .par_iter()
        .enumerate()
        .try_for_each(|(i, slashable_attestation)| {
            verify_slashable_attestation(&state, slashable_attestation, spec)
                .map_err(|e| e.into_with_index(i))
        })?;
    let all_slashable_attestations_have_been_checked = true;

    // Gather the slashable indices and preform the final verification and update the state in series.
    for (i, attester_slashing) in attester_slashings.iter().enumerate() {
        let should_verify_slashable_attestations = !all_slashable_attestations_have_been_checked;

        verify_attester_slashing(
            &state,
            &attester_slashing,
            should_verify_slashable_attestations,
            spec,
        )
        .map_err(|e| e.into_with_index(i))?;

        let slashable_indices = gather_attester_slashing_indices(&state, &attester_slashing, spec)
            .map_err(|e| e.into_with_index(i))?;

        for i in slashable_indices {
            slash_validator(state, i as usize, spec)?;
        }
    }

    Ok(())
}

/// Validates each `Attestation` and updates the state, short-circuiting on an invalid object.
///
/// Returns `Ok(())` if the validation and state updates completed successfully, otherwise returns
/// an `Err` describing the invalid object or cause of failure.
///
/// Spec v0.5.0
pub fn process_attestations(
    state: &mut BeaconState,
    attestations: &[Attestation],
    spec: &ChainSpec,
) -> Result<(), Error> {
    verify!(
        attestations.len() as u64 <= spec.max_attestations,
        Invalid::MaxAttestationsExceeded
    );

    // Ensure the previous epoch cache exists.
    state.build_epoch_cache(RelativeEpoch::Previous, spec)?;

    // Verify attestations in parallel.
    attestations
        .par_iter()
        .enumerate()
        .try_for_each(|(i, attestation)| {
            validate_attestation(state, attestation, spec).map_err(|e| e.into_with_index(i))
        })?;

    // Update the state in series.
    for attestation in attestations {
        let pending_attestation = PendingAttestation::from_attestation(attestation, state.slot);
        let attestation_epoch = attestation.data.slot.epoch(spec.slots_per_epoch);

        if attestation_epoch == state.current_epoch(spec) {
            state.current_epoch_attestations.push(pending_attestation)
        } else if attestation_epoch == state.previous_epoch(spec) {
            state.previous_epoch_attestations.push(pending_attestation)
        }
    }

    Ok(())
}

/// Validates each `Deposit` and updates the state, short-circuiting on an invalid object.
///
/// Returns `Ok(())` if the validation and state updates completed successfully, otherwise returns
/// an `Err` describing the invalid object or cause of failure.
///
/// Spec v0.5.0
pub fn process_deposits(
    state: &mut BeaconState,
    deposits: &[Deposit],
    spec: &ChainSpec,
) -> Result<(), Error> {
    verify!(
        deposits.len() as u64 <= spec.max_deposits,
        Invalid::MaxDepositsExceeded
    );

    // Verify deposits in parallel.
    deposits
        .par_iter()
        .enumerate()
        .try_for_each(|(i, deposit)| {
            verify_deposit(state, deposit, VERIFY_DEPOSIT_MERKLE_PROOFS, spec)
                .map_err(|e| e.into_with_index(i))
        })?;

    // Check `state.deposit_index` and update the state in series.
    for (i, deposit) in deposits.iter().enumerate() {
        verify_deposit_index(state, deposit).map_err(|e| e.into_with_index(i))?;

        // Ensure the state's pubkey cache is fully up-to-date, it will be used to check to see if the
        // depositing validator already exists in the registry.
        state.update_pubkey_cache()?;

        // Get an `Option<u64>` where `u64` is the validator index if this deposit public key
        // already exists in the beacon_state.
        //
        // This function also verifies the withdrawal credentials.
        let validator_index =
            get_existing_validator_index(state, deposit).map_err(|e| e.into_with_index(i))?;

        let deposit_data = &deposit.deposit_data;
        let deposit_input = &deposit.deposit_data.deposit_input;

        if let Some(index) = validator_index {
            // Update the existing validator balance.
            safe_add_assign!(
                state.validator_balances[index as usize],
                deposit_data.amount
            );
        } else {
            // Create a new validator.
            let validator = Validator {
                pubkey: deposit_input.pubkey.clone(),
                withdrawal_credentials: deposit_input.withdrawal_credentials,
                activation_epoch: spec.far_future_epoch,
                exit_epoch: spec.far_future_epoch,
                withdrawable_epoch: spec.far_future_epoch,
                initiated_exit: false,
                slashed: false,
            };
            state.validator_registry.push(validator);
            state.validator_balances.push(deposit_data.amount);
        }

        state.deposit_index += 1;
    }

    Ok(())
}

/// Validates each `Exit` and updates the state, short-circuiting on an invalid object.
///
/// Returns `Ok(())` if the validation and state updates completed successfully, otherwise returns
/// an `Err` describing the invalid object or cause of failure.
///
/// Spec v0.5.0
pub fn process_exits(
    state: &mut BeaconState,
    voluntary_exits: &[VoluntaryExit],
    spec: &ChainSpec,
) -> Result<(), Error> {
    verify!(
        voluntary_exits.len() as u64 <= spec.max_voluntary_exits,
        Invalid::MaxExitsExceeded
    );

    // Verify exits in parallel.
    voluntary_exits
        .par_iter()
        .enumerate()
        .try_for_each(|(i, exit)| {
            verify_exit(&state, exit, spec).map_err(|e| e.into_with_index(i))
        })?;

    // Update the state in series.
    for exit in voluntary_exits {
        state.initiate_validator_exit(exit.validator_index as usize);
    }

    Ok(())
}

/// Validates each `Transfer` and updates the state, short-circuiting on an invalid object.
///
/// Returns `Ok(())` if the validation and state updates completed successfully, otherwise returns
/// an `Err` describing the invalid object or cause of failure.
///
/// Spec v0.5.0
pub fn process_transfers(
    state: &mut BeaconState,
    transfers: &[Transfer],
    spec: &ChainSpec,
) -> Result<(), Error> {
    verify!(
        transfers.len() as u64 <= spec.max_transfers,
        Invalid::MaxTransfersExceed
    );

    transfers
        .par_iter()
        .enumerate()
        .try_for_each(|(i, transfer)| {
            verify_transfer(&state, transfer, spec).map_err(|e| e.into_with_index(i))
        })?;

    for (i, transfer) in transfers.iter().enumerate() {
        execute_transfer(state, transfer, spec).map_err(|e| e.into_with_index(i))?;
    }

    Ok(())
}
