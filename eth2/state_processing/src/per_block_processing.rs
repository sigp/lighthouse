use self::verify_proposer_slashing::verify_proposer_slashing;
use errors::{BlockInvalid as Invalid, BlockProcessingError as Error, IntoWithIndex};
use hashing::hash;
use rayon::prelude::*;
use ssz::{ssz_encode, SignedRoot, TreeHash};
use types::*;

pub use self::verify_attester_slashing::{
    gather_attester_slashing_indices, verify_attester_slashing,
};
pub use validate_attestation::{validate_attestation, validate_attestation_without_signature};
pub use verify_deposit::{
    build_public_key_hashmap, get_existing_validator_index, verify_deposit, verify_deposit_index,
};
pub use verify_exit::verify_exit;
pub use verify_transfer::{execute_transfer, verify_transfer};

pub mod errors;
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
/// Spec v0.4.0
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
/// Spec v0.4.0
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
/// Spec v0.4.0
fn per_block_processing_signature_optional(
    mut state: &mut BeaconState,
    block: &BeaconBlock,
    should_verify_block_signature: bool,
    spec: &ChainSpec,
) -> Result<(), Error> {
    // Verify that `block.slot == state.slot`.
    verify!(block.slot == state.slot, Invalid::StateSlotMismatch);

    // Ensure the current and previous epoch cache is built.
    state.build_epoch_cache(RelativeEpoch::Current, spec)?;
    state.build_epoch_cache(RelativeEpoch::Previous, spec)?;

    if should_verify_block_signature {
        verify_block_signature(&state, &block, &spec)?;
    }
    process_randao(&mut state, &block, &spec)?;
    process_eth1_data(&mut state, &block.eth1_data)?;
    process_proposer_slashings(&mut state, &block.body.proposer_slashings, spec)?;
    process_attester_slashings(&mut state, &block.body.attester_slashings, spec)?;
    process_attestations(&mut state, &block.body.attestations, spec)?;
    process_deposits(&mut state, &block.body.deposits, spec)?;
    process_exits(&mut state, &block.body.voluntary_exits, spec)?;
    process_transfers(&mut state, &block.body.transfers, spec)?;

    Ok(())
}

/// Verifies the signature of a block.
///
/// Spec v0.4.0
pub fn verify_block_signature(
    state: &BeaconState,
    block: &BeaconBlock,
    spec: &ChainSpec,
) -> Result<(), Error> {
    let block_proposer =
        &state.validator_registry[state.get_beacon_proposer_index(block.slot, spec)?];

    let proposal = Proposal {
        slot: block.slot,
        shard: spec.beacon_chain_shard_number,
        block_root: Hash256::from_slice(&block.signed_root()[..]),
        signature: block.signature.clone(),
    };
    let domain = spec.get_domain(
        block.slot.epoch(spec.slots_per_epoch),
        Domain::Proposal,
        &state.fork,
    );

    verify!(
        proposal
            .signature
            .verify(&proposal.signed_root()[..], domain, &block_proposer.pubkey),
        Invalid::BadSignature
    );

    Ok(())
}

/// Verifies the `randao_reveal` against the block's proposer pubkey and updates
/// `state.latest_randao_mixes`.
///
/// Spec v0.4.0
pub fn process_randao(
    state: &mut BeaconState,
    block: &BeaconBlock,
    spec: &ChainSpec,
) -> Result<(), Error> {
    // Let `proposer = state.validator_registry[get_beacon_proposer_index(state, state.slot)]`.
    let block_proposer =
        &state.validator_registry[state.get_beacon_proposer_index(block.slot, spec)?];

    // Verify that `bls_verify(pubkey=proposer.pubkey,
    // message_hash=hash_tree_root(get_current_epoch(state)), signature=block.randao_reveal,
    // domain=get_domain(state.fork, get_current_epoch(state), DOMAIN_RANDAO))`.
    verify!(
        block.randao_reveal.verify(
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

    // Update the state's RANDAO mix with the one revealed in the block.
    update_randao(state, &block.randao_reveal, spec)?;

    Ok(())
}

/// Update the `state.eth1_data_votes` based upon the `eth1_data` provided.
///
/// Spec v0.4.0
pub fn process_eth1_data(state: &mut BeaconState, eth1_data: &Eth1Data) -> Result<(), Error> {
    // Either increment the eth1_data vote count, or add a new eth1_data.
    let matching_eth1_vote_index = state
        .eth1_data_votes
        .iter()
        .position(|vote| vote.eth1_data == *eth1_data);
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

/// Updates the present randao mix.
///
/// Set `state.latest_randao_mixes[get_current_epoch(state) % LATEST_RANDAO_MIXES_LENGTH] =
/// xor(get_randao_mix(state, get_current_epoch(state)), hash(block.randao_reveal))`.
///
/// Spec v0.4.0
pub fn update_randao(
    state: &mut BeaconState,
    reveal: &Signature,
    spec: &ChainSpec,
) -> Result<(), BeaconStateError> {
    let hashed_reveal = {
        let encoded_signature = ssz_encode(reveal);
        Hash256::from_slice(&hash(&encoded_signature[..])[..])
    };

    let current_epoch = state.slot.epoch(spec.slots_per_epoch);

    let current_mix = state
        .get_randao_mix(current_epoch, spec)
        .ok_or_else(|| BeaconStateError::InsufficientRandaoMixes)?;

    let new_mix = *current_mix ^ hashed_reveal;

    let index = current_epoch.as_usize() % spec.latest_randao_mixes_length;

    if index < state.latest_randao_mixes.len() {
        state.latest_randao_mixes[index] = new_mix;
        Ok(())
    } else {
        Err(BeaconStateError::InsufficientRandaoMixes)
    }
}

/// Validates each `ProposerSlashing` and updates the state, short-circuiting on an invalid object.
///
/// Returns `Ok(())` if the validation and state updates completed successfully, otherwise returns
/// an `Err` describing the invalid object or cause of failure.
///
/// Spec v0.4.0
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

    for proposer_slashing in proposer_slashings {
        state.slash_validator(proposer_slashing.proposer_index as usize, spec)?;
    }

    Ok(())
}

/// Validates each `AttesterSlsashing` and updates the state, short-circuiting on an invalid object.
///
/// Returns `Ok(())` if the validation and state updates completed successfully, otherwise returns
/// an `Err` describing the invalid object or cause of failure.
///
/// Spec v0.4.0
pub fn process_attester_slashings(
    state: &mut BeaconState,
    attester_slashings: &[AttesterSlashing],
    spec: &ChainSpec,
) -> Result<(), Error> {
    verify!(
        attester_slashings.len() as u64 <= spec.max_attester_slashings,
        Invalid::MaxAttesterSlashingsExceed
    );

    // Verify attester slashings in parallel.
    attester_slashings
        .par_iter()
        .enumerate()
        .try_for_each(|(i, attester_slashing)| {
            verify_attester_slashing(&state, &attester_slashing, spec)
                .map_err(|e| e.into_with_index(i))
        })?;

    // Gather the slashable indices and update the state in series.
    for (i, attester_slashing) in attester_slashings.iter().enumerate() {
        let slashable_indices = gather_attester_slashing_indices(&state, &attester_slashing)
            .map_err(|e| e.into_with_index(i))?;
        for i in slashable_indices {
            state.slash_validator(i as usize, spec)?;
        }
    }

    Ok(())
}

/// Validates each `Attestation` and updates the state, short-circuiting on an invalid object.
///
/// Returns `Ok(())` if the validation and state updates completed successfully, otherwise returns
/// an `Err` describing the invalid object or cause of failure.
///
/// Spec v0.4.0
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
        let pending_attestation = PendingAttestation {
            data: attestation.data.clone(),
            aggregation_bitfield: attestation.aggregation_bitfield.clone(),
            custody_bitfield: attestation.custody_bitfield.clone(),
            inclusion_slot: state.slot,
        };
        state.latest_attestations.push(pending_attestation);
    }

    Ok(())
}

/// Validates each `Deposit` and updates the state, short-circuiting on an invalid object.
///
/// Returns `Ok(())` if the validation and state updates completed successfully, otherwise returns
/// an `Err` describing the invalid object or cause of failure.
///
/// Spec v0.4.0
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

    let public_key_to_index_hashmap = build_public_key_hashmap(&state);

    // Check `state.deposit_index` and update the state in series.
    for (i, deposit) in deposits.iter().enumerate() {
        verify_deposit_index(state, deposit).map_err(|e| e.into_with_index(i))?;

        // Get an `Option<u64>` where `u64` is the validator index if this deposit public key
        // already exists in the beacon_state.
        //
        // This function also verifies the withdrawal credentials.
        let validator_index =
            get_existing_validator_index(state, deposit, &public_key_to_index_hashmap)
                .map_err(|e| e.into_with_index(i))?;

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
                withdrawal_credentials: deposit_input.withdrawal_credentials.clone(),
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
/// Spec v0.4.0
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
/// Spec v0.4.0
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
