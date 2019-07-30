use crate::common::{initiate_validator_exit, slash_validator};
use errors::{BlockInvalid as Invalid, BlockProcessingError as Error, IntoWithIndex};
use rayon::prelude::*;
use std::collections::HashSet;
use std::iter::FromIterator;
use tree_hash::{SignedRoot, TreeHash};
use types::*;

pub use self::verify_attester_slashing::{
    get_slashable_indices, get_slashable_indices_modular, verify_attester_slashing,
};
pub use self::verify_proposer_slashing::verify_proposer_slashing;
pub use is_valid_indexed_attestation::{
    is_valid_indexed_attestation, is_valid_indexed_attestation_without_signature,
};
pub use verify_attestation::{
    verify_attestation, verify_attestation_time_independent_only,
    verify_attestation_without_signature,
};
pub use verify_deposit::{
    get_existing_validator_index, verify_deposit_merkle_proof, verify_deposit_signature,
};
pub use verify_exit::{verify_exit, verify_exit_time_independent_only};
pub use verify_transfer::{
    execute_transfer, verify_transfer, verify_transfer_time_independent_only,
};

pub mod block_processing_builder;
pub mod errors;
mod is_valid_indexed_attestation;
pub mod tests;
mod verify_attestation;
mod verify_attester_slashing;
mod verify_deposit;
mod verify_exit;
mod verify_proposer_slashing;
mod verify_transfer;

/// Updates the state for a new block, whilst validating that the block is valid.
///
/// Returns `Ok(())` if the block is valid and the state was successfully updated. Otherwise
/// returns an error describing why the block was invalid or how the function failed to execute.
///
/// Spec v0.8.0
pub fn per_block_processing<T: EthSpec>(
    state: &mut BeaconState<T>,
    block: &BeaconBlock<T>,
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
/// Spec v0.8.0
pub fn per_block_processing_without_verifying_block_signature<T: EthSpec>(
    state: &mut BeaconState<T>,
    block: &BeaconBlock<T>,
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
/// Spec v0.8.0
fn per_block_processing_signature_optional<T: EthSpec>(
    mut state: &mut BeaconState<T>,
    block: &BeaconBlock<T>,
    should_verify_block_signature: bool,
    spec: &ChainSpec,
) -> Result<(), Error> {
    process_block_header(state, block, spec, should_verify_block_signature)?;

    // Ensure the current and previous epoch caches are built.
    state.build_committee_cache(RelativeEpoch::Previous, spec)?;
    state.build_committee_cache(RelativeEpoch::Current, spec)?;

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
/// Spec v0.8.0
pub fn process_block_header<T: EthSpec>(
    state: &mut BeaconState<T>,
    block: &BeaconBlock<T>,
    spec: &ChainSpec,
    should_verify_block_signature: bool,
) -> Result<(), Error> {
    verify!(block.slot == state.slot, Invalid::StateSlotMismatch);

    let expected_previous_block_root =
        Hash256::from_slice(&state.latest_block_header.signed_root());
    verify!(
        block.parent_root == expected_previous_block_root,
        Invalid::ParentBlockRootMismatch {
            state: expected_previous_block_root,
            block: block.parent_root,
        }
    );

    state.latest_block_header = block.temporary_block_header();

    // Verify proposer is not slashed
    let proposer_idx = state.get_beacon_proposer_index(block.slot, RelativeEpoch::Current, spec)?;
    let proposer = &state.validators[proposer_idx];
    verify!(!proposer.slashed, Invalid::ProposerSlashed(proposer_idx));

    if should_verify_block_signature {
        verify_block_signature(&state, &block, &spec)?;
    }

    Ok(())
}

/// Verifies the signature of a block.
///
/// Spec v0.8.0
pub fn verify_block_signature<T: EthSpec>(
    state: &BeaconState<T>,
    block: &BeaconBlock<T>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let block_proposer = &state.validators
        [state.get_beacon_proposer_index(block.slot, RelativeEpoch::Current, spec)?];

    let domain = spec.get_domain(
        block.slot.epoch(T::slots_per_epoch()),
        Domain::BeaconProposer,
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
/// Spec v0.8.0
pub fn process_randao<T: EthSpec>(
    state: &mut BeaconState<T>,
    block: &BeaconBlock<T>,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let block_proposer = &state.validators
        [state.get_beacon_proposer_index(block.slot, RelativeEpoch::Current, spec)?];

    // Verify RANDAO reveal.
    verify!(
        block.body.randao_reveal.verify(
            &state.current_epoch().tree_hash_root()[..],
            spec.get_domain(
                block.slot.epoch(T::slots_per_epoch()),
                Domain::Randao,
                &state.fork
            ),
            &block_proposer.pubkey
        ),
        Invalid::BadRandaoSignature
    );

    // Update the current epoch RANDAO mix.
    state.update_randao_mix(state.current_epoch(), &block.body.randao_reveal)?;

    Ok(())
}

/// Update the `state.eth1_data_votes` based upon the `eth1_data` provided.
///
/// Spec v0.8.0
pub fn process_eth1_data<T: EthSpec>(
    state: &mut BeaconState<T>,
    eth1_data: &Eth1Data,
) -> Result<(), Error> {
    state.eth1_data_votes.push(eth1_data.clone())?;

    let num_votes = state
        .eth1_data_votes
        .iter()
        .filter(|vote| *vote == eth1_data)
        .count();

    if num_votes * 2 > T::SlotsPerEth1VotingPeriod::to_usize() {
        state.eth1_data = eth1_data.clone();
    }

    Ok(())
}

/// Validates each `ProposerSlashing` and updates the state, short-circuiting on an invalid object.
///
/// Returns `Ok(())` if the validation and state updates completed successfully, otherwise returns
/// an `Err` describing the invalid object or cause of failure.
///
/// Spec v0.8.0
pub fn process_proposer_slashings<T: EthSpec>(
    state: &mut BeaconState<T>,
    proposer_slashings: &[ProposerSlashing],
    spec: &ChainSpec,
) -> Result<(), Error> {
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
        slash_validator(state, proposer_slashing.proposer_index as usize, None, spec)?;
    }

    Ok(())
}

/// Validates each `AttesterSlashing` and updates the state, short-circuiting on an invalid object.
///
/// Returns `Ok(())` if the validation and state updates completed successfully, otherwise returns
/// an `Err` describing the invalid object or cause of failure.
///
/// Spec v0.8.0
pub fn process_attester_slashings<T: EthSpec>(
    state: &mut BeaconState<T>,
    attester_slashings: &[AttesterSlashing<T>],
    spec: &ChainSpec,
) -> Result<(), Error> {
    // Verify the `IndexedAttestation`s in parallel (these are the resource-consuming objects, not
    // the `AttesterSlashing`s themselves).
    let mut indexed_attestations: Vec<&_> = Vec::with_capacity(attester_slashings.len() * 2);
    for attester_slashing in attester_slashings {
        indexed_attestations.push(&attester_slashing.attestation_1);
        indexed_attestations.push(&attester_slashing.attestation_2);
    }

    // Verify indexed attestations in parallel.
    indexed_attestations
        .par_iter()
        .enumerate()
        .try_for_each(|(i, indexed_attestation)| {
            is_valid_indexed_attestation(&state, indexed_attestation, spec)
                .map_err(|e| e.into_with_index(i))
        })?;
    let all_indexed_attestations_have_been_checked = true;

    // Gather the indexed indices and preform the final verification and update the state in series.
    for (i, attester_slashing) in attester_slashings.iter().enumerate() {
        let should_verify_indexed_attestations = !all_indexed_attestations_have_been_checked;

        verify_attester_slashing(
            &state,
            &attester_slashing,
            should_verify_indexed_attestations,
            spec,
        )
        .map_err(|e| e.into_with_index(i))?;

        let slashable_indices =
            get_slashable_indices(&state, &attester_slashing).map_err(|e| e.into_with_index(i))?;

        for i in slashable_indices {
            slash_validator(state, i as usize, None, spec)?;
        }
    }

    Ok(())
}

/// Validates each `Attestation` and updates the state, short-circuiting on an invalid object.
///
/// Returns `Ok(())` if the validation and state updates completed successfully, otherwise returns
/// an `Err` describing the invalid object or cause of failure.
///
/// Spec v0.8.0
pub fn process_attestations<T: EthSpec>(
    state: &mut BeaconState<T>,
    attestations: &[Attestation<T>],
    spec: &ChainSpec,
) -> Result<(), Error> {
    // Ensure the previous epoch cache exists.
    state.build_committee_cache(RelativeEpoch::Previous, spec)?;

    // Verify attestations in parallel.
    attestations
        .par_iter()
        .enumerate()
        .try_for_each(|(i, attestation)| {
            verify_attestation(state, attestation, spec).map_err(|e| e.into_with_index(i))
        })?;

    // Update the state in series.
    let proposer_index =
        state.get_beacon_proposer_index(state.slot, RelativeEpoch::Current, spec)? as u64;
    for attestation in attestations {
        let attestation_slot = state.get_attestation_data_slot(&attestation.data)?;
        let pending_attestation = PendingAttestation {
            aggregation_bits: attestation.aggregation_bits.clone(),
            data: attestation.data.clone(),
            inclusion_delay: (state.slot - attestation_slot).as_u64(),
            proposer_index,
        };

        if attestation.data.target.epoch == state.current_epoch() {
            state.current_epoch_attestations.push(pending_attestation)?;
        } else {
            state
                .previous_epoch_attestations
                .push(pending_attestation)?;
        }
    }

    Ok(())
}

/// Validates each `Deposit` and updates the state, short-circuiting on an invalid object.
///
/// Returns `Ok(())` if the validation and state updates completed successfully, otherwise returns
/// an `Err` describing the invalid object or cause of failure.
///
/// Spec v0.8.0
pub fn process_deposits<T: EthSpec>(
    state: &mut BeaconState<T>,
    deposits: &[Deposit],
    spec: &ChainSpec,
) -> Result<(), Error> {
    verify!(
        deposits.len() as u64
            == std::cmp::min(
                T::MaxDeposits::to_u64(),
                state.eth1_data.deposit_count - state.eth1_deposit_index
            ),
        Invalid::DepositCountInvalid
    );

    // Verify merkle proofs in parallel.
    deposits
        .par_iter()
        .enumerate()
        .try_for_each(|(i, deposit)| {
            verify_deposit_merkle_proof(state, deposit, state.eth1_deposit_index + i as u64, spec)
                .map_err(|e| e.into_with_index(i))
        })?;

    // Update the state in series.
    for deposit in deposits {
        process_deposit(state, deposit, spec, false)?;
    }

    Ok(())
}

/// Process a single deposit, optionally verifying its merkle proof.
///
/// Spec v0.8.1
pub fn process_deposit<T: EthSpec>(
    state: &mut BeaconState<T>,
    deposit: &Deposit,
    spec: &ChainSpec,
    verify_merkle_proof: bool,
) -> Result<(), Error> {
    let deposit_index = state.eth1_deposit_index as usize;
    if verify_merkle_proof {
        verify_deposit_merkle_proof(state, deposit, state.eth1_deposit_index, spec)
            .map_err(|e| e.into_with_index(deposit_index))?;
    }

    state.eth1_deposit_index += 1;

    // Ensure the state's pubkey cache is fully up-to-date, it will be used to check to see if the
    // depositing validator already exists in the registry.
    state.update_pubkey_cache()?;

    // Get an `Option<u64>` where `u64` is the validator index if this deposit public key
    // already exists in the beacon_state.
    let validator_index = get_existing_validator_index(state, deposit)
        .map_err(|e| e.into_with_index(deposit_index))?;

    let amount = deposit.data.amount;

    if let Some(index) = validator_index {
        // Update the existing validator balance.
        safe_add_assign!(state.balances[index as usize], amount);
    } else {
        // The signature should be checked for new validators. Return early for a bad
        // signature.
        if verify_deposit_signature(state, deposit, spec).is_err() {
            return Ok(());
        }

        // Create a new validator.
        let validator = Validator {
            pubkey: deposit.data.pubkey.clone(),
            withdrawal_credentials: deposit.data.withdrawal_credentials,
            activation_eligibility_epoch: spec.far_future_epoch,
            activation_epoch: spec.far_future_epoch,
            exit_epoch: spec.far_future_epoch,
            withdrawable_epoch: spec.far_future_epoch,
            effective_balance: std::cmp::min(
                amount - amount % spec.effective_balance_increment,
                spec.max_effective_balance,
            ),
            slashed: false,
        };
        state.validators.push(validator)?;
        state.balances.push(deposit.data.amount)?;
    }

    Ok(())
}

/// Validates each `Exit` and updates the state, short-circuiting on an invalid object.
///
/// Returns `Ok(())` if the validation and state updates completed successfully, otherwise returns
/// an `Err` describing the invalid object or cause of failure.
///
/// Spec v0.8.0
pub fn process_exits<T: EthSpec>(
    state: &mut BeaconState<T>,
    voluntary_exits: &[VoluntaryExit],
    spec: &ChainSpec,
) -> Result<(), Error> {
    // Verify exits in parallel.
    voluntary_exits
        .par_iter()
        .enumerate()
        .try_for_each(|(i, exit)| {
            verify_exit(&state, exit, spec).map_err(|e| e.into_with_index(i))
        })?;

    // Update the state in series.
    for exit in voluntary_exits {
        initiate_validator_exit(state, exit.validator_index as usize, spec)?;
    }

    Ok(())
}

/// Validates each `Transfer` and updates the state, short-circuiting on an invalid object.
///
/// Returns `Ok(())` if the validation and state updates completed successfully, otherwise returns
/// an `Err` describing the invalid object or cause of failure.
///
/// Spec v0.8.0
pub fn process_transfers<T: EthSpec>(
    state: &mut BeaconState<T>,
    transfers: &[Transfer],
    spec: &ChainSpec,
) -> Result<(), Error> {
    // Verify that there are no duplicate transfers
    verify!(
        transfers.len() == HashSet::<_>::from_iter(transfers).len(),
        Invalid::DuplicateTransfers
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
