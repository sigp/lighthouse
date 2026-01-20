use self::errors::ExecutionPayloadBidInvalid;
use crate::consensus_context::ConsensusContext;
use errors::{BlockOperationError, BlockProcessingError, HeaderInvalid};
use rayon::prelude::*;
use safe_arith::{ArithError, SafeArith, SafeArithIter};
use signature_sets::{
    block_proposal_signature_set, execution_payload_bid_signature_set, get_pubkey_from_state,
    randao_signature_set,
};
use std::borrow::Cow;
use tree_hash::TreeHash;
use typenum::Unsigned;
use types::consts::gloas::BUILDER_INDEX_FLAG;
use types::*;

pub use self::verify_attester_slashing::{
    get_slashable_indices, get_slashable_indices_modular, verify_attester_slashing,
};
pub use self::verify_proposer_slashing::verify_proposer_slashing;
pub use altair::sync_committee::process_sync_aggregate;
pub use block_signature_verifier::{BlockSignatureVerifier, ParallelSignatureSets};
pub use is_valid_indexed_attestation::is_valid_indexed_attestation;
pub use is_valid_indexed_payload_attestation::is_valid_indexed_payload_attestation;
pub use process_operations::process_operations;
pub use verify_attestation::{
    verify_attestation_for_block_inclusion, verify_attestation_for_state,
};
pub use verify_bls_to_execution_change::verify_bls_to_execution_change;
pub use verify_deposit::{
    get_existing_validator_index, is_valid_deposit_signature, verify_deposit_merkle_proof,
};
pub use verify_exit::verify_exit;

pub mod altair;
pub mod block_signature_verifier;
pub mod deneb;
pub mod errors;
mod is_valid_indexed_attestation;
mod is_valid_indexed_payload_attestation;
pub mod process_operations;
pub mod process_withdrawals;
pub mod signature_sets;
pub mod tests;
mod verify_attestation;
mod verify_attester_slashing;
mod verify_bls_to_execution_change;
mod verify_deposit;
mod verify_exit;
mod verify_payload_attestation;
mod verify_proposer_slashing;

use crate::common::update_progressive_balances_cache::{
    initialize_progressive_balances_cache, update_progressive_balances_metrics,
};
use crate::epoch_cache::initialize_epoch_cache;
#[cfg(feature = "arbitrary-fuzz")]
use arbitrary::Arbitrary;
use tracing::instrument;

/// The strategy to be used when validating the block's signatures.
#[cfg_attr(feature = "arbitrary-fuzz", derive(Arbitrary))]
#[derive(PartialEq, Clone, Copy, Debug)]
pub enum BlockSignatureStrategy {
    /// Do not validate any signature. Use with caution.
    NoVerification,
    /// Validate each signature individually, as its object is being processed.
    VerifyIndividual,
    /// Validate only the randao reveal signature.
    VerifyRandao,
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

/// Control verification of the latest block header.
#[cfg_attr(feature = "arbitrary-fuzz", derive(Arbitrary))]
#[derive(PartialEq, Clone, Copy)]
pub enum VerifyBlockRoot {
    True,
    False,
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
#[instrument(skip_all)]
pub fn per_block_processing<E: EthSpec, Payload: AbstractExecPayload<E>>(
    state: &mut BeaconState<E>,
    signed_block: &SignedBeaconBlock<E, Payload>,
    block_signature_strategy: BlockSignatureStrategy,
    verify_block_root: VerifyBlockRoot,
    ctxt: &mut ConsensusContext<E>,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    let block = signed_block.message();

    // Verify that the `SignedBeaconBlock` instantiation matches the fork at `signed_block.slot()`.
    signed_block
        .fork_name(spec)
        .map_err(BlockProcessingError::InconsistentBlockFork)?;

    // Verify that the `BeaconState` instantiation matches the fork at `state.slot()`.
    state
        .fork_name(spec)
        .map_err(BlockProcessingError::InconsistentStateFork)?;

    // Build epoch cache if it hasn't already been built, or if it is no longer valid
    initialize_epoch_cache(state, spec)?;
    initialize_progressive_balances_cache(state, spec)?;
    state.build_slashings_cache()?;

    let verify_signatures = match block_signature_strategy {
        BlockSignatureStrategy::VerifyBulk => {
            // Verify all signatures in the block at once.
            block_verify!(
                BlockSignatureVerifier::verify_entire_block(
                    state,
                    |i| get_pubkey_from_state(state, i),
                    |pk_bytes| pk_bytes.decompress().ok().map(Cow::Owned),
                    signed_block,
                    ctxt,
                    spec
                )
                .is_ok(),
                BlockProcessingError::BulkSignatureVerificationFailed
            );
            VerifySignatures::False
        }
        BlockSignatureStrategy::VerifyIndividual => VerifySignatures::True,
        BlockSignatureStrategy::NoVerification => VerifySignatures::False,
        BlockSignatureStrategy::VerifyRandao => VerifySignatures::False,
    };

    let proposer_index = process_block_header(
        state,
        block.temporary_block_header(),
        verify_block_root,
        ctxt,
        spec,
    )?;

    if verify_signatures.is_true() {
        verify_block_signature(state, signed_block, ctxt, spec)?;
    }

    let verify_randao = if let BlockSignatureStrategy::VerifyRandao = block_signature_strategy {
        VerifySignatures::True
    } else {
        verify_signatures
    };
    // Ensure the current and previous epoch committee caches are built.
    state.build_committee_cache(RelativeEpoch::Previous, spec)?;
    state.build_committee_cache(RelativeEpoch::Current, spec)?;

    // The call to the `process_execution_payload` must happen before the call to the
    // `process_randao` as the former depends on the `randao_mix` computed with the reveal of the
    // previous block.
    if is_execution_enabled(state, block.body()) {
        let body = block.body();
        if state.fork_name_unchecked().gloas_enabled() {
            process_withdrawals::gloas::process_withdrawals::<E>(state, spec)?;
            process_execution_payload_bid(state, block, verify_signatures, spec)?;
        } else {
            process_withdrawals::capella::process_withdrawals::<E, Payload>(
                state,
                body.execution_payload()?,
                spec,
            )?;
            process_execution_payload::<E, Payload>(state, body, spec)?;
        }
    }

    process_randao(state, block, verify_randao, ctxt, spec)?;
    process_eth1_data(state, block.body().eth1_data())?;
    process_operations(state, block.body(), verify_signatures, ctxt, spec)?;

    if let Ok(sync_aggregate) = block.body().sync_aggregate() {
        process_sync_aggregate(
            state,
            sync_aggregate,
            proposer_index,
            verify_signatures,
            spec,
        )?;
    }

    if is_progressive_balances_enabled(state) {
        update_progressive_balances_metrics(state.progressive_balances_cache())?;
    }

    Ok(())
}

/// Processes the block header, returning the proposer index.
pub fn process_block_header<E: EthSpec>(
    state: &mut BeaconState<E>,
    block_header: BeaconBlockHeader,
    verify_block_root: VerifyBlockRoot,
    ctxt: &mut ConsensusContext<E>,
    spec: &ChainSpec,
) -> Result<u64, BlockOperationError<HeaderInvalid>> {
    // Verify that the slots match
    verify!(
        block_header.slot == state.slot(),
        HeaderInvalid::StateSlotMismatch
    );

    // Verify that the block is newer than the latest block header
    verify!(
        block_header.slot > state.latest_block_header().slot,
        HeaderInvalid::OlderThanLatestBlockHeader {
            block_slot: block_header.slot,
            latest_block_header_slot: state.latest_block_header().slot,
        }
    );

    // Verify that proposer index is the correct index
    let proposer_index = block_header.proposer_index;
    let state_proposer_index = ctxt.get_proposer_index(state, spec)?;
    verify!(
        proposer_index == state_proposer_index,
        HeaderInvalid::ProposerIndexMismatch {
            block_proposer_index: proposer_index,
            state_proposer_index,
        }
    );

    if verify_block_root == VerifyBlockRoot::True {
        let expected_previous_block_root = state.latest_block_header().tree_hash_root();
        verify!(
            block_header.parent_root == expected_previous_block_root,
            HeaderInvalid::ParentBlockRootMismatch {
                state: expected_previous_block_root,
                block: block_header.parent_root,
            }
        );
    }

    state
        .slashings_cache_mut()
        .update_latest_block_slot(block_header.slot);
    *state.latest_block_header_mut() = block_header;

    // Verify proposer is not slashed
    verify!(
        !state.get_validator(proposer_index as usize)?.slashed,
        HeaderInvalid::ProposerSlashed(proposer_index)
    );

    Ok(proposer_index)
}

/// Verifies the signature of a block.
///
/// Spec v0.12.1
pub fn verify_block_signature<E: EthSpec, Payload: AbstractExecPayload<E>>(
    state: &BeaconState<E>,
    block: &SignedBeaconBlock<E, Payload>,
    ctxt: &mut ConsensusContext<E>,
    spec: &ChainSpec,
) -> Result<(), BlockOperationError<HeaderInvalid>> {
    let block_root = Some(ctxt.get_current_block_root(block)?);
    let proposer_index = Some(ctxt.get_proposer_index(state, spec)?);
    verify!(
        block_proposal_signature_set(
            state,
            |i| get_pubkey_from_state(state, i),
            block,
            block_root,
            proposer_index,
            spec
        )?
        .verify(),
        HeaderInvalid::ProposalSignatureInvalid
    );

    Ok(())
}

/// Verifies the `randao_reveal` against the block's proposer pubkey and updates
/// `state.latest_randao_mixes`.
pub fn process_randao<E: EthSpec, Payload: AbstractExecPayload<E>>(
    state: &mut BeaconState<E>,
    block: BeaconBlockRef<'_, E, Payload>,
    verify_signatures: VerifySignatures,
    ctxt: &mut ConsensusContext<E>,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    if verify_signatures.is_true() {
        // Verify RANDAO reveal signature.
        let proposer_index = ctxt.get_proposer_index(state, spec)?;
        block_verify!(
            randao_signature_set(
                state,
                |i| get_pubkey_from_state(state, i),
                block,
                Some(proposer_index),
                spec
            )?
            .verify(),
            BlockProcessingError::RandaoSignatureInvalid
        );
    }

    // Update the current epoch RANDAO mix.
    state.update_randao_mix(state.current_epoch(), block.body().randao_reveal())?;

    Ok(())
}

/// Update the `state.eth1_data_votes` based upon the `eth1_data` provided.
pub fn process_eth1_data<E: EthSpec>(
    state: &mut BeaconState<E>,
    eth1_data: &Eth1Data,
) -> Result<(), BeaconStateError> {
    if let Some(new_eth1_data) = get_new_eth1_data(state, eth1_data)? {
        *state.eth1_data_mut() = new_eth1_data;
    }

    state.eth1_data_votes_mut().push(eth1_data.clone())?;

    Ok(())
}

/// Returns `Ok(Some(eth1_data))` if adding the given `eth1_data` to `state.eth1_data_votes` would
/// result in a change to `state.eth1_data`.
pub fn get_new_eth1_data<E: EthSpec>(
    state: &BeaconState<E>,
    eth1_data: &Eth1Data,
) -> Result<Option<Eth1Data>, ArithError> {
    let num_votes = state
        .eth1_data_votes()
        .iter()
        .filter(|vote| *vote == eth1_data)
        .count();

    // The +1 is to account for the `eth1_data` supplied to the function.
    if num_votes.safe_add(1)?.safe_mul(2)? > E::SlotsPerEth1VotingPeriod::to_usize() {
        Ok(Some(eth1_data.clone()))
    } else {
        Ok(None)
    }
}

/// Performs *partial* verification of the `payload`.
///
/// The verification is partial, since the execution payload is not verified against an execution
/// engine. That is expected to be performed by an upstream function.
///
/// ## Specification
///
/// Contains a partial set of checks from the `process_execution_payload` function:
///
/// https://github.com/ethereum/consensus-specs/blob/v1.1.5/specs/merge/beacon-chain.md#process_execution_payload
pub fn partially_verify_execution_payload<E: EthSpec, Payload: AbstractExecPayload<E>>(
    state: &BeaconState<E>,
    block_slot: Slot,
    body: BeaconBlockBodyRef<E, Payload>,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    let payload = body.execution_payload()?;
    if is_merge_transition_complete(state) {
        block_verify!(
            payload.parent_hash() == state.latest_execution_payload_header()?.block_hash(),
            BlockProcessingError::ExecutionHashChainIncontiguous {
                expected: state.latest_execution_payload_header()?.block_hash(),
                found: payload.parent_hash(),
            }
        );
    }
    block_verify!(
        payload.prev_randao() == *state.get_randao_mix(state.current_epoch())?,
        BlockProcessingError::ExecutionRandaoMismatch {
            expected: *state.get_randao_mix(state.current_epoch())?,
            found: payload.prev_randao(),
        }
    );

    let timestamp = compute_timestamp_at_slot(state, block_slot, spec)?;
    block_verify!(
        payload.timestamp() == timestamp,
        BlockProcessingError::ExecutionInvalidTimestamp {
            expected: timestamp,
            found: payload.timestamp(),
        }
    );

    if let Ok(blob_commitments) = body.blob_kzg_commitments() {
        // Verify commitments are under the limit.
        let max_blobs_per_block =
            spec.max_blobs_per_block(block_slot.epoch(E::slots_per_epoch())) as usize;
        block_verify!(
            blob_commitments.len() <= max_blobs_per_block,
            BlockProcessingError::ExecutionInvalidBlobsLen {
                max: max_blobs_per_block,
                actual: blob_commitments.len(),
            }
        );
    }

    Ok(())
}

/// Calls `partially_verify_execution_payload` and then updates the payload header in the `state`.
///
/// ## Specification
///
/// Partially equivalent to the `process_execution_payload` function:
///
/// https://github.com/ethereum/consensus-specs/blob/v1.1.5/specs/merge/beacon-chain.md#process_execution_payload
pub fn process_execution_payload<E: EthSpec, Payload: AbstractExecPayload<E>>(
    state: &mut BeaconState<E>,
    body: BeaconBlockBodyRef<E, Payload>,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    partially_verify_execution_payload::<E, Payload>(state, state.slot(), body, spec)?;
    let payload = body.execution_payload()?;
    match state.latest_execution_payload_header_mut()? {
        ExecutionPayloadHeaderRefMut::Bellatrix(header_mut) => {
            match payload.to_execution_payload_header() {
                ExecutionPayloadHeader::Bellatrix(header) => *header_mut = header,
                _ => return Err(BlockProcessingError::IncorrectStateType),
            }
        }
        ExecutionPayloadHeaderRefMut::Capella(header_mut) => {
            match payload.to_execution_payload_header() {
                ExecutionPayloadHeader::Capella(header) => *header_mut = header,
                _ => return Err(BlockProcessingError::IncorrectStateType),
            }
        }
        ExecutionPayloadHeaderRefMut::Deneb(header_mut) => {
            match payload.to_execution_payload_header() {
                ExecutionPayloadHeader::Deneb(header) => *header_mut = header,
                _ => return Err(BlockProcessingError::IncorrectStateType),
            }
        }
        ExecutionPayloadHeaderRefMut::Electra(header_mut) => {
            match payload.to_execution_payload_header() {
                ExecutionPayloadHeader::Electra(header) => *header_mut = header,
                _ => return Err(BlockProcessingError::IncorrectStateType),
            }
        }
        ExecutionPayloadHeaderRefMut::Fulu(header_mut) => {
            match payload.to_execution_payload_header() {
                ExecutionPayloadHeader::Fulu(header) => *header_mut = header,
                _ => return Err(BlockProcessingError::IncorrectStateType),
            }
        }
    }

    Ok(())
}

/// These functions will definitely be called before the merge. Their entire purpose is to check if
/// the merge has happened or if we're on the transition block. Thus we don't want to propagate
/// errors from the `BeaconState` being an earlier variant than `BeaconStateBellatrix` as we'd have to
/// repeatedly write code to treat these errors as false.
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/bellatrix/beacon-chain.md#is_merge_transition_complete
pub fn is_merge_transition_complete<E: EthSpec>(state: &BeaconState<E>) -> bool {
    // TODO(EIP7732): check this cause potuz modified this function for god knows what reason
    if state.fork_name_unchecked().capella_enabled() {
        true
    } else if state.fork_name_unchecked().bellatrix_enabled() {
        // We must check defaultness against the payload header with 0x0 roots, as that's what's meant
        // by `ExecutionPayloadHeader()` in the spec.
        state
            .latest_execution_payload_header()
            .map(|header| !header.is_default_with_zero_roots())
            .unwrap_or(false)
    } else {
        false
    }
}
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/bellatrix/beacon-chain.md#is_merge_transition_block
pub fn is_merge_transition_block<E: EthSpec, Payload: AbstractExecPayload<E>>(
    state: &BeaconState<E>,
    body: BeaconBlockBodyRef<E, Payload>,
) -> bool {
    // For execution payloads in blocks (which may be headers) we must check defaultness against
    // the payload with `transactions_root` equal to the tree hash of the empty list.
    body.execution_payload()
        .map(|payload| {
            !is_merge_transition_complete(state) && !payload.is_default_with_empty_roots()
        })
        .unwrap_or(false)
}
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/bellatrix/beacon-chain.md#is_execution_enabled
pub fn is_execution_enabled<E: EthSpec, Payload: AbstractExecPayload<E>>(
    state: &BeaconState<E>,
    body: BeaconBlockBodyRef<E, Payload>,
) -> bool {
    is_merge_transition_block(state, body) || is_merge_transition_complete(state)
}

/// https://github.com/ethereum/consensus-specs/blob/dev/specs/bellatrix/beacon-chain.md#compute_timestamp_at_slot
pub fn compute_timestamp_at_slot<E: EthSpec>(
    state: &BeaconState<E>,
    block_slot: Slot,
    spec: &ChainSpec,
) -> Result<u64, ArithError> {
    let slots_since_genesis = block_slot.as_u64().safe_sub(spec.genesis_slot.as_u64())?;
    slots_since_genesis
        .safe_mul(spec.seconds_per_slot)
        .and_then(|since_genesis| state.genesis_time().safe_add(since_genesis))
}

pub fn convert_builder_index_to_validator_index(builder_index: BuilderIndex) -> u64 {
    builder_index | BUILDER_INDEX_FLAG
}

pub fn convert_validator_index_to_builder_index(validator_index: u64) -> BuilderIndex {
    validator_index & !BUILDER_INDEX_FLAG
}

pub fn get_balance_after_withdrawals<E: EthSpec>(
    state: &BeaconState<E>,
    validator_index: u64,
    withdrawals: &[Withdrawal],
) -> Result<u64, BeaconStateError> {
    let withdrawn = withdrawals
        .iter()
        .filter(|withdrawal| withdrawal.validator_index == validator_index)
        .map(|withdrawal| withdrawal.amount)
        .safe_sum()?;
    state
        .get_balance(validator_index as usize)?
        .safe_sub(withdrawn)
        .map_err(Into::into)
}

fn is_eligible_for_partial_withdrawals(
    validator: &Validator,
    balance: u64,
    spec: &ChainSpec,
) -> bool {
    let has_sufficient_effective_balance =
        validator.effective_balance >= spec.min_activation_balance;
    let has_excess_balance = balance > spec.min_activation_balance;
    validator.exit_epoch == spec.far_future_epoch
        && has_sufficient_effective_balance
        && has_excess_balance
}

pub fn get_builder_withdrawals<E: EthSpec>(
    state: &BeaconState<E>,
    withdrawal_index: &mut u64,
    withdrawals: &mut Vec<Withdrawal>,
) -> Result<Option<usize>, BlockProcessingError> {
    let Ok(builder_pending_withdrawals) = state.builder_pending_withdrawals() else {
        // Pre-Gloas, nothing to do.
        return Ok(None);
    };

    let withdrawals_limit = E::max_withdrawals_per_payload();

    let mut processed_count = 0;
    for withdrawal in builder_pending_withdrawals {
        let has_reached_limit = withdrawals.len() == withdrawals_limit;

        if has_reached_limit {
            break;
        }

        let builder_index = withdrawal.builder_index;

        withdrawals.push(Withdrawal {
            index: *withdrawal_index,
            validator_index: convert_builder_index_to_validator_index(builder_index),
            address: withdrawal.fee_recipient,
            amount: withdrawal.amount,
        });
        withdrawal_index.safe_add_assign(1)?;
        processed_count.safe_add_assign(1)?;
    }
    Ok(Some(processed_count))
}

pub fn get_pending_partial_withdrawals<E: EthSpec>(
    state: &BeaconState<E>,
    withdrawal_index: &mut u64,
    withdrawals: &mut Vec<Withdrawal>,
    spec: &ChainSpec,
) -> Result<Option<usize>, BlockProcessingError> {
    let Ok(pending_partial_withdrawals) = state.pending_partial_withdrawals() else {
        // Pre-Electra nothing to do.
        return Ok(None);
    };
    let epoch = state.current_epoch();

    let withdrawals_limit = std::cmp::min(
        withdrawals
            .len()
            .safe_add(spec.max_pending_partials_per_withdrawals_sweep as usize)?,
        E::max_withdrawals_per_payload(),
    );

    block_verify!(
        withdrawals.len() <= withdrawals_limit,
        BlockProcessingError::WithdrawalsLimitExceeded {
            limit: withdrawals_limit,
            prior_withdrawals: withdrawals.len()
        }
    );

    let mut processed_count = 0;
    for withdrawal in pending_partial_withdrawals {
        let is_withdrawable = withdrawal.withdrawable_epoch <= epoch;
        let has_reached_limit = withdrawals.len() >= withdrawals_limit;

        if !is_withdrawable || has_reached_limit {
            break;
        }

        let validator_index = withdrawal.validator_index;
        let validator = state.get_validator(validator_index as usize)?;
        let balance = get_balance_after_withdrawals(state, validator_index, withdrawals)?;

        if is_eligible_for_partial_withdrawals(validator, balance, spec) {
            let withdrawal_amount = std::cmp::min(
                balance.safe_sub(spec.min_activation_balance)?,
                withdrawal.amount,
            );
            withdrawals.push(Withdrawal {
                index: *withdrawal_index,
                validator_index,
                address: validator
                    .get_execution_withdrawal_address(spec, state.fork_name_unchecked())
                    .ok_or(BeaconStateError::NonExecutionAddressWithdrawalCredential)?,
                amount: withdrawal_amount,
            });
            withdrawal_index.safe_add_assign(1)?;
        }
        processed_count.safe_add_assign(1)?;
    }

    Ok(Some(processed_count))
}

/// Get withdrawals from the validator sweep.
///
/// This function iterates through validators starting from `next_withdrawal_validator_index`
/// and adds full or partial withdrawals for eligible validators.
///
/// https://ethereum.github.io/consensus-specs/specs/capella/beacon-chain/#new-get_validators_sweep_withdrawals
pub fn get_validators_sweep_withdrawals<E: EthSpec>(
    state: &BeaconState<E>,
    withdrawal_index: &mut u64,
    withdrawals: &mut Vec<Withdrawal>,
    spec: &ChainSpec,
) -> Result<u64, BlockProcessingError> {
    let epoch = state.current_epoch();
    let fork_name = state.fork_name_unchecked();
    let mut validator_index = state.next_withdrawal_validator_index()?;
    let validators_limit = std::cmp::min(
        state.validators().len() as u64,
        spec.max_validators_per_withdrawals_sweep,
    );
    let withdrawals_limit = E::max_withdrawals_per_payload();

    // There must be at least one space reserved for validator sweep withdrawals
    block_verify!(
        withdrawals.len() < withdrawals_limit,
        BlockProcessingError::WithdrawalsLimitExceeded {
            limit: withdrawals_limit,
            prior_withdrawals: withdrawals.len()
        }
    );

    let mut processed_count: u64 = 0;

    for _ in 0..validators_limit {
        if withdrawals.len() >= withdrawals_limit {
            break;
        }

        let validator = state.get_validator(validator_index as usize)?;
        let balance = get_balance_after_withdrawals(state, validator_index, withdrawals)?;

        if validator.is_fully_withdrawable_validator(balance, epoch, spec, fork_name) {
            withdrawals.push(Withdrawal {
                index: *withdrawal_index,
                validator_index,
                address: validator
                    .get_execution_withdrawal_address(spec, fork_name)
                    .ok_or(BlockProcessingError::WithdrawalCredentialsInvalid)?,
                amount: balance,
            });
            withdrawal_index.safe_add_assign(1)?;
        } else if validator.is_partially_withdrawable_validator(balance, spec, fork_name) {
            withdrawals.push(Withdrawal {
                index: *withdrawal_index,
                validator_index,
                address: validator
                    .get_execution_withdrawal_address(spec, fork_name)
                    .ok_or(BlockProcessingError::WithdrawalCredentialsInvalid)?,
                amount: balance.safe_sub(validator.get_max_effective_balance(spec, fork_name))?,
            });
            withdrawal_index.safe_add_assign(1)?;
        }

        validator_index = validator_index
            .safe_add(1)?
            .safe_rem(state.validators().len() as u64)?;
        processed_count.safe_add_assign(1)?;
    }

    Ok(processed_count)
}

/// Compute the next batch of withdrawals which should be included in a block.
///
/// https://ethereum.github.io/consensus-specs/specs/gloas/beacon-chain/#modified-get_expected_withdrawals
#[allow(clippy::type_complexity)]
pub fn get_expected_withdrawals<E: EthSpec>(
    state: &BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(Withdrawals<E>, Option<usize>, Option<usize>, u64), BlockProcessingError> {
    let mut withdrawal_index = state.next_withdrawal_index()?;
    let mut withdrawals = Vec::<Withdrawal>::with_capacity(E::max_withdrawals_per_payload());

    // [New in Gloas:EIP7732]
    // Get builder withdrawals
    let processed_builder_withdrawals_count =
        get_builder_withdrawals(state, &mut withdrawal_index, &mut withdrawals)?;

    // [New in Electra:EIP7251]
    // Get partial withdrawals.
    let processed_partial_withdrawals_count =
        get_pending_partial_withdrawals(state, &mut withdrawal_index, &mut withdrawals, spec)?;

    // Get validators sweep withdrawals
    let processed_validators_sweep_count =
        get_validators_sweep_withdrawals(state, &mut withdrawal_index, &mut withdrawals, spec)?;

    Ok((
        withdrawals
            .try_into()
            .map_err(BlockProcessingError::SszTypesError)?,
        processed_builder_withdrawals_count,
        processed_partial_withdrawals_count,
        processed_validators_sweep_count,
    ))
}

pub fn process_execution_payload_bid<E: EthSpec, Payload: AbstractExecPayload<E>>(
    state: &mut BeaconState<E>,
    block: BeaconBlockRef<'_, E, Payload>,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    // Verify the bid signature
    let signed_bid = block.body().signed_execution_payload_bid()?;

    let bid = &signed_bid.message;
    let amount = bid.value;
    let builder_index = bid.builder_index;
    let builder = state.get_validator(builder_index as usize)?;

    // For self-builds, amount must be zero regardless of withdrawal credential prefix
    if builder_index == block.proposer_index() {
        block_verify!(amount == 0, ExecutionPayloadBidInvalid::BadAmount.into());
        // TODO(EIP-7732): check with team if we should use ExecutionPayloadBidInvalid::BadSignature or a new error variant for this, like BadSelfBuildSignature
        block_verify!(
            signed_bid.signature.is_infinity(),
            ExecutionPayloadBidInvalid::BadSignature.into()
        );
    } else {
        // Non-self builds require builder withdrawal credential
        block_verify!(
            builder.has_builder_withdrawal_credential(spec),
            ExecutionPayloadBidInvalid::BadWithdrawalCredentials.into()
        );
        if verify_signatures.is_true() {
            block_verify!(
                execution_payload_bid_signature_set(
                    state,
                    |i| get_pubkey_from_state(state, i),
                    signed_bid,
                    spec
                )?
                .verify(),
                ExecutionPayloadBidInvalid::BadSignature.into()
            );
        }
    }

    // Verify builder is active and not slashed
    block_verify!(
        builder.is_active_at(state.current_epoch()),
        ExecutionPayloadBidInvalid::BuilderNotActive(builder_index).into()
    );
    block_verify!(
        !builder.slashed,
        ExecutionPayloadBidInvalid::BuilderSlashed(builder_index).into()
    );

    // Only perform payment related checks if amount > 0
    if amount > 0 {
        // Check that the builder has funds to cover the bid
        let pending_payments = state
            .builder_pending_payments()?
            .iter()
            .filter_map(|payment| {
                if payment.withdrawal.builder_index == builder_index {
                    Some(payment.withdrawal.amount)
                } else {
                    None
                }
            })
            .safe_sum()?;

        let pending_withdrawals = state
            .builder_pending_withdrawals()?
            .iter()
            .filter_map(|withdrawal| {
                if withdrawal.builder_index == builder_index {
                    Some(withdrawal.amount)
                } else {
                    None
                }
            })
            .safe_sum()?;

        let builder_balance = state.get_balance(builder_index as usize)?;

        block_verify!(
            builder_balance
                >= amount
                    .safe_add(pending_payments)?
                    .safe_add(pending_withdrawals)?
                    .safe_add(spec.min_activation_balance)?,
            ExecutionPayloadBidInvalid::InsufficientBalance {
                builder_index,
                builder_balance,
                bid_value: amount,
            }
            .into()
        );
    }

    // Verify that the bid is for the current slot
    block_verify!(
        bid.slot == block.slot(),
        ExecutionPayloadBidInvalid::SlotMismatch {
            state_slot: block.slot(),
            bid_slot: bid.slot,
        }
        .into()
    );

    // Verify that the bid is for the right parent block
    let latest_block_hash = state.latest_block_hash()?;
    block_verify!(
        bid.parent_block_hash == *latest_block_hash,
        ExecutionPayloadBidInvalid::ParentBlockHashMismatch {
            state_block_hash: *latest_block_hash,
            bid_parent_hash: bid.parent_block_hash,
        }
        .into()
    );

    block_verify!(
        bid.parent_block_root == block.parent_root(),
        ExecutionPayloadBidInvalid::ParentBlockRootMismatch {
            block_parent_root: block.parent_root(),
            bid_parent_root: bid.parent_block_root,
        }
        .into()
    );

    // Record the pending payment if there is some payment
    if amount > 0 {
        let pending_payment = BuilderPendingPayment {
            weight: 0,
            withdrawal: BuilderPendingWithdrawal {
                fee_recipient: bid.fee_recipient,
                amount,
                builder_index,
            },
        };

        let payment_index = (E::slots_per_epoch()
            .safe_add(bid.slot.as_u64().safe_rem(E::slots_per_epoch())?)?)
            as usize;

        *state
            .builder_pending_payments_mut()?
            .get_mut(payment_index)
            .ok_or(BlockProcessingError::BeaconStateError(
                BeaconStateError::BuilderPendingPaymentsIndexNotSupported(payment_index),
            ))? = pending_payment;
    }

    // Cache the execution bid
    *state.latest_execution_payload_bid_mut()? = bid.clone();

    Ok(())
}
