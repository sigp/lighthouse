use crate::common::{initiate_validator_exit, slash_validator};
use errors::{BlockOperationError, BlockProcessingError, HeaderInvalid, IntoWithIndex};
use rayon::prelude::*;
use safe_arith::{ArithError, SafeArith};
use signature_sets::{block_proposal_signature_set, get_pubkey_from_state, randao_signature_set};
use std::convert::TryInto;
use tree_hash::TreeHash;
use types::*;

pub use self::verify_attester_slashing::{
    get_slashable_indices, get_slashable_indices_modular, verify_attester_slashing,
};
pub use self::verify_proposer_slashing::verify_proposer_slashing;
pub use block_signature_verifier::BlockSignatureVerifier;
pub use is_valid_indexed_attestation::is_valid_indexed_attestation;
pub use verify_attestation::{
    verify_attestation_for_block_inclusion, verify_attestation_for_state,
};
pub use verify_deposit::{
    get_existing_validator_index, verify_deposit_merkle_proof, verify_deposit_signature,
};
pub use verify_exit::{verify_exit, verify_exit_time_independent_only};

pub mod block_processing_builder;
pub mod block_signature_verifier;
pub mod errors;
mod is_valid_indexed_attestation;
pub mod signature_sets;
pub mod tests;
mod verify_attestation;
mod verify_attester_slashing;
mod verify_deposit;
mod verify_exit;
mod verify_proposer_slashing;

#[cfg(feature = "arbitrary-fuzz")]
use arbitrary::Arbitrary;

/// The strategy to be used when validating the block's signatures.
#[cfg_attr(feature = "arbitrary-fuzz", derive(Arbitrary))]
#[derive(PartialEq, Clone, Copy)]
pub enum BlockSignatureStrategy {
    /// Do not validate any signature. Use with caution.
    NoVerification,
    /// Validate each signature individually, as its object is being processed.
    VerifyIndividual,
    /// Verify all signatures in bulk at the beginning of block processing.
    VerifyBulk,
}

/// The strategy to be used when validating the block's signatures.
#[cfg_attr(feature = "arbitrary-fuzz", derive(Arbitrary))]
#[derive(PartialEq, Clone, Copy)]
pub enum VerifySignatures {
    /// Validate all signatures encountered.
    True,
    /// Do not validate any signature. Use with caution.
    False,
}

impl VerifySignatures {
    pub fn is_true(self) -> bool {
        self == VerifySignatures::True
    }
}

/// Updates the state for a new block, whilst validating that the block is valid, optionally
/// checking the block proposer signature.
///
/// Returns `Ok(())` if the block is valid and the state was successfully updated. Otherwise
/// returns an error describing why the block was invalid or how the function failed to execute.
///
/// If `block_root` is `Some`, this root is used for verification of the proposer's signature. If it
/// is `None` the signing root is computed from scratch. This parameter only exists to avoid
/// re-calculating the root when it is already known. Note `block_root` should be equal to the
/// tree hash root of the block, NOT the signing root of the block. This function takes
/// care of mixing in the domain.
///
/// Spec v0.11.1
pub fn per_block_processing<T: EthSpec>(
    mut state: &mut BeaconState<T>,
    signed_block: &SignedBeaconBlock<T>,
    block_root: Option<Hash256>,
    block_signature_strategy: BlockSignatureStrategy,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    let block = &signed_block.message;
    let verify_signatures = match block_signature_strategy {
        BlockSignatureStrategy::VerifyBulk => {
            // Verify all signatures in the block at once.
            block_verify!(
                BlockSignatureVerifier::verify_entire_block(
                    state,
                    |i| get_pubkey_from_state(state, i),
                    signed_block,
                    block_root,
                    spec
                )
                .is_ok(),
                BlockProcessingError::BulkSignatureVerificationFailed
            );
            VerifySignatures::False
        }
        BlockSignatureStrategy::VerifyIndividual => VerifySignatures::True,
        BlockSignatureStrategy::NoVerification => VerifySignatures::False,
    };

    process_block_header(state, block, spec)?;

    if verify_signatures.is_true() {
        verify_block_signature(&state, signed_block, block_root, &spec)?;
    }

    // Ensure the current and previous epoch caches are built.
    state.build_committee_cache(RelativeEpoch::Previous, spec)?;
    state.build_committee_cache(RelativeEpoch::Current, spec)?;

    process_randao(&mut state, &block, verify_signatures, &spec)?;
    process_eth1_data(&mut state, &block.body.eth1_data)?;
    process_proposer_slashings(
        &mut state,
        &block.body.proposer_slashings,
        verify_signatures,
        spec,
    )?;
    process_attester_slashings(
        &mut state,
        &block.body.attester_slashings,
        verify_signatures,
        spec,
    )?;
    process_attestations(
        &mut state,
        &block.body.attestations,
        verify_signatures,
        spec,
    )?;
    process_deposits(&mut state, &block.body.deposits, spec)?;
    process_exits(
        &mut state,
        &block.body.voluntary_exits,
        verify_signatures,
        spec,
    )?;

    Ok(())
}

/// Processes the block header.
///
/// Spec v0.11.1
pub fn process_block_header<T: EthSpec>(
    state: &mut BeaconState<T>,
    block: &BeaconBlock<T>,
    spec: &ChainSpec,
) -> Result<(), BlockOperationError<HeaderInvalid>> {
    // Verify that the slots match
    verify!(block.slot == state.slot, HeaderInvalid::StateSlotMismatch);

    // Verify that proposer index is the correct index
    let proposer_index = block.proposer_index as usize;
    let state_proposer_index = state.get_beacon_proposer_index(block.slot, spec)?;
    verify!(
        proposer_index == state_proposer_index,
        HeaderInvalid::ProposerIndexMismatch {
            block_proposer_index: proposer_index,
            state_proposer_index,
        }
    );

    let expected_previous_block_root = state.latest_block_header.tree_hash_root();
    verify!(
        block.parent_root == expected_previous_block_root,
        HeaderInvalid::ParentBlockRootMismatch {
            state: expected_previous_block_root,
            block: block.parent_root,
        }
    );

    state.latest_block_header = block.temporary_block_header();

    // Verify proposer is not slashed
    let proposer = &state.validators[proposer_index];
    verify!(
        !proposer.slashed,
        HeaderInvalid::ProposerSlashed(proposer_index)
    );

    Ok(())
}

/// Verifies the signature of a block.
///
/// Spec v0.11.1
pub fn verify_block_signature<T: EthSpec>(
    state: &BeaconState<T>,
    block: &SignedBeaconBlock<T>,
    block_root: Option<Hash256>,
    spec: &ChainSpec,
) -> Result<(), BlockOperationError<HeaderInvalid>> {
    verify!(
        block_proposal_signature_set(
            state,
            |i| get_pubkey_from_state(state, i),
            block,
            block_root,
            spec
        )?
        .is_valid(),
        HeaderInvalid::ProposalSignatureInvalid
    );

    Ok(())
}

/// Verifies the `randao_reveal` against the block's proposer pubkey and updates
/// `state.latest_randao_mixes`.
///
/// Spec v0.11.1
pub fn process_randao<T: EthSpec>(
    state: &mut BeaconState<T>,
    block: &BeaconBlock<T>,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    if verify_signatures.is_true() {
        // Verify RANDAO reveal signature.
        block_verify!(
            randao_signature_set(state, |i| get_pubkey_from_state(state, i), block, spec)?
                .is_valid(),
            BlockProcessingError::RandaoSignatureInvalid
        );
    }

    // Update the current epoch RANDAO mix.
    state.update_randao_mix(state.current_epoch(), &block.body.randao_reveal)?;

    Ok(())
}

/// Update the `state.eth1_data_votes` based upon the `eth1_data` provided.
///
/// Spec v0.11.1
pub fn process_eth1_data<T: EthSpec>(
    state: &mut BeaconState<T>,
    eth1_data: &Eth1Data,
) -> Result<(), Error> {
    if let Some(new_eth1_data) = get_new_eth1_data(state, eth1_data)? {
        state.eth1_data = new_eth1_data;
    }

    state.eth1_data_votes.push(eth1_data.clone())?;

    Ok(())
}

/// Returns `Ok(Some(eth1_data))` if adding the given `eth1_data` to `state.eth1_data_votes` would
/// result in a change to `state.eth1_data`.
///
/// Spec v0.11.1
pub fn get_new_eth1_data<T: EthSpec>(
    state: &BeaconState<T>,
    eth1_data: &Eth1Data,
) -> Result<Option<Eth1Data>, ArithError> {
    let num_votes = state
        .eth1_data_votes
        .iter()
        .filter(|vote| *vote == eth1_data)
        .count();

    // The +1 is to account for the `eth1_data` supplied to the function.
    if num_votes.safe_add(1)?.safe_mul(2)? > T::SlotsPerEth1VotingPeriod::to_usize() {
        Ok(Some(eth1_data.clone()))
    } else {
        Ok(None)
    }
}

/// Validates each `ProposerSlashing` and updates the state, short-circuiting on an invalid object.
///
/// Returns `Ok(())` if the validation and state updates completed successfully, otherwise returns
/// an `Err` describing the invalid object or cause of failure.
///
/// Spec v0.11.1
pub fn process_proposer_slashings<T: EthSpec>(
    state: &mut BeaconState<T>,
    proposer_slashings: &[ProposerSlashing],
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    // Verify and apply proposer slashings in series.
    // We have to verify in series because an invalid block may contain multiple slashings
    // for the same validator, and we need to correctly detect and reject that.
    proposer_slashings
        .into_iter()
        .enumerate()
        .try_for_each(|(i, proposer_slashing)| {
            verify_proposer_slashing(proposer_slashing, &state, verify_signatures, spec)
                .map_err(|e| e.into_with_index(i))?;

            slash_validator(
                state,
                proposer_slashing.signed_header_1.message.proposer_index as usize,
                None,
                spec,
            )?;

            Ok(())
        })
}

/// Validates each `AttesterSlashing` and updates the state, short-circuiting on an invalid object.
///
/// Returns `Ok(())` if the validation and state updates completed successfully, otherwise returns
/// an `Err` describing the invalid object or cause of failure.
///
/// Spec v0.11.1
pub fn process_attester_slashings<T: EthSpec>(
    state: &mut BeaconState<T>,
    attester_slashings: &[AttesterSlashing<T>],
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    // Verify the `IndexedAttestation`s in parallel (these are the resource-consuming objects, not
    // the `AttesterSlashing`s themselves).
    let mut indexed_attestations: Vec<&_> =
        Vec::with_capacity(attester_slashings.len().safe_mul(2)?);
    for attester_slashing in attester_slashings {
        indexed_attestations.push(&attester_slashing.attestation_1);
        indexed_attestations.push(&attester_slashing.attestation_2);
    }

    // Verify indexed attestations in parallel.
    indexed_attestations
        .par_iter()
        .enumerate()
        .try_for_each(|(i, indexed_attestation)| {
            is_valid_indexed_attestation(&state, indexed_attestation, verify_signatures, spec)
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
            verify_signatures,
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
/// Spec v0.11.1
pub fn process_attestations<T: EthSpec>(
    state: &mut BeaconState<T>,
    attestations: &[Attestation<T>],
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    // Ensure the previous epoch cache exists.
    state.build_committee_cache(RelativeEpoch::Previous, spec)?;

    // Verify attestations in parallel.
    attestations
        .par_iter()
        .enumerate()
        .try_for_each(|(i, attestation)| {
            verify_attestation_for_block_inclusion(state, attestation, verify_signatures, spec)
                .map_err(|e| e.into_with_index(i))
        })?;

    // Update the state in series.
    let proposer_index = state.get_beacon_proposer_index(state.slot, spec)? as u64;
    for attestation in attestations {
        let pending_attestation = PendingAttestation {
            aggregation_bits: attestation.aggregation_bits.clone(),
            data: attestation.data.clone(),
            inclusion_delay: (state.slot - attestation.data.slot).as_u64(),
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
/// Spec v0.11.1
pub fn process_deposits<T: EthSpec>(
    state: &mut BeaconState<T>,
    deposits: &[Deposit],
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    let expected_deposit_len = std::cmp::min(
        T::MaxDeposits::to_u64(),
        state.get_outstanding_deposit_len()?,
    );
    block_verify!(
        deposits.len() as u64 == expected_deposit_len,
        BlockProcessingError::DepositCountInvalid {
            expected: expected_deposit_len as usize,
            found: deposits.len(),
        }
    );

    // Verify merkle proofs in parallel.
    deposits
        .par_iter()
        .enumerate()
        .try_for_each(|(i, deposit)| {
            verify_deposit_merkle_proof(
                state,
                deposit,
                state.eth1_deposit_index.safe_add(i as u64)?,
                spec,
            )
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
/// Spec v0.11.1
pub fn process_deposit<T: EthSpec>(
    state: &mut BeaconState<T>,
    deposit: &Deposit,
    spec: &ChainSpec,
    verify_merkle_proof: bool,
) -> Result<(), BlockProcessingError> {
    let deposit_index = state.eth1_deposit_index as usize;
    if verify_merkle_proof {
        verify_deposit_merkle_proof(state, deposit, state.eth1_deposit_index, spec)
            .map_err(|e| e.into_with_index(deposit_index))?;
    }

    state.eth1_deposit_index.increment()?;

    // Ensure the state's pubkey cache is fully up-to-date, it will be used to check to see if the
    // depositing validator already exists in the registry.
    state.update_pubkey_cache()?;

    let pubkey: PublicKey = match (&deposit.data.pubkey).try_into() {
        Err(_) => return Ok(()), //bad public key => return early
        Ok(k) => k,
    };
    // Get an `Option<u64>` where `u64` is the validator index if this deposit public key
    // already exists in the beacon_state.
    let validator_index = get_existing_validator_index(state, &deposit.data.pubkey)
        .map_err(|e| e.into_with_index(deposit_index))?;

    let amount = deposit.data.amount;

    if let Some(index) = validator_index {
        // Update the existing validator balance.
        safe_add_assign!(state.balances[index as usize], amount);
    } else {
        // The signature should be checked for new validators. Return early for a bad
        // signature.
        if verify_deposit_signature(&deposit.data, spec).is_err() {
            return Ok(());
        }

        // Create a new validator.
        let validator = Validator {
            pubkey: pubkey.into(),
            withdrawal_credentials: deposit.data.withdrawal_credentials,
            activation_eligibility_epoch: spec.far_future_epoch,
            activation_epoch: spec.far_future_epoch,
            exit_epoch: spec.far_future_epoch,
            withdrawable_epoch: spec.far_future_epoch,
            effective_balance: std::cmp::min(
                amount.safe_sub(amount.safe_rem(spec.effective_balance_increment)?)?,
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
/// Spec v0.11.1
pub fn process_exits<T: EthSpec>(
    state: &mut BeaconState<T>,
    voluntary_exits: &[SignedVoluntaryExit],
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    // Verify exits in parallel.
    voluntary_exits
        .par_iter()
        .enumerate()
        .try_for_each(|(i, exit)| {
            verify_exit(&state, exit, verify_signatures, spec).map_err(|e| e.into_with_index(i))
        })?;

    // Update the state in series.
    for exit in voluntary_exits {
        initiate_validator_exit(state, exit.message.validator_index as usize, spec)?;
    }

    Ok(())
}
