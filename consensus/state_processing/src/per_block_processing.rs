use crate::common::{decrease_balance, increase_balance};
use crate::consensus_context::ConsensusContext;
use errors::{BlockOperationError, BlockProcessingError, ExecutionBidInvalid, HeaderInvalid};
use rayon::prelude::*;
use safe_arith::{ArithError, SafeArith};
use signature_sets::{
    block_proposal_signature_set, execution_bid_signature_set, get_pubkey_from_state,
    randao_signature_set,
};
use std::borrow::Cow;
use tree_hash::TreeHash;
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
pub use verify_payload_attestation::verify_payload_attestation;

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
        if state.fork_name_unchecked().eip7732_enabled() {
            process_withdrawals::eip7732::process_withdrawals::<E>(state, spec)?;
        } else {
            process_withdrawals::capella::process_withdrawals::<E, Payload>(
                state,
                body.execution_payload()?,
                spec,
            )?;
            process_execution_payload::<E, Payload>(state, body, spec)?;
        }
    }

    process_execution_bid(state, block, verify_signatures, spec)?;
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
) -> Result<(), Error> {
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
        block_verify!(
            blob_commitments.len() <= E::max_blobs_per_block(),
            BlockProcessingError::ExecutionInvalidBlobsLen {
                max: E::max_blobs_per_block(),
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
    }

    Ok(())
}

/// These functions will definitely be called before the merge. Their entire purpose is to check if
/// the merge has happened or if we're on the transition block. Thus we don't want to propagate
/// errors from the `BeaconState` being an earlier variant than `BeaconStateBellatrix` as we'd have to
/// repeatedly write code to treat these errors as false.
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/bellatrix/beacon-chain.md#is_merge_transition_complete
pub fn is_merge_transition_complete<E: EthSpec>(state: &BeaconState<E>) -> bool {
    match state {
        // We must check defaultness against the payload header with 0x0 roots, as that's what's meant
        // by `ExecutionPayloadHeader()` in the spec.
        BeaconState::Bellatrix(_) => state
            .latest_execution_payload_header()
            .map(|header| !header.is_default_with_zero_roots())
            .unwrap_or(false),
        BeaconState::Electra(_) | BeaconState::Deneb(_) | BeaconState::Capella(_) => true,
        BeaconState::Base(_) | BeaconState::Altair(_) => false,
        // TODO(EIP7732): check this cause potuz modified this function for god knows what reason
        BeaconState::EIP7732(_) => true,
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

/// Compute the next batch of withdrawals which should be included in a block.
///
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/capella/beacon-chain.md#new-get_expected_withdrawals
pub fn get_expected_withdrawals<E: EthSpec>(
    state: &BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(Withdrawals<E>, Option<usize>), BlockProcessingError> {
    let epoch = state.current_epoch();
    let mut withdrawal_index = state.next_withdrawal_index()?;
    let mut validator_index = state.next_withdrawal_validator_index()?;
    let mut withdrawals = vec![];
    let fork_name = state.fork_name_unchecked();

    // [New in Electra:EIP7251]
    // Consume pending partial withdrawals
    let partial_withdrawals_count =
        if let Ok(partial_withdrawals) = state.pending_partial_withdrawals() {
            for withdrawal in partial_withdrawals {
                if withdrawal.withdrawable_epoch > epoch
                    || withdrawals.len() == spec.max_pending_partials_per_withdrawals_sweep as usize
                {
                    break;
                }

                let withdrawal_balance = state.get_balance(withdrawal.index as usize)?;
                let validator = state.get_validator(withdrawal.index as usize)?;

                let has_sufficient_effective_balance =
                    validator.effective_balance >= spec.min_activation_balance;
                let has_excess_balance = withdrawal_balance > spec.min_activation_balance;

                if validator.exit_epoch == spec.far_future_epoch
                    && has_sufficient_effective_balance
                    && has_excess_balance
                {
                    let withdrawable_balance = std::cmp::min(
                        withdrawal_balance.safe_sub(spec.min_activation_balance)?,
                        withdrawal.amount,
                    );
                    withdrawals.push(Withdrawal {
                        index: withdrawal_index,
                        validator_index: withdrawal.index,
                        address: validator
                            .get_execution_withdrawal_address(spec)
                            .ok_or(BeaconStateError::NonExecutionAddresWithdrawalCredential)?,
                        amount: withdrawable_balance,
                    });
                    withdrawal_index.safe_add_assign(1)?;
                }
            }
            Some(withdrawals.len())
        } else {
            None
        };

    let bound = std::cmp::min(
        state.validators().len() as u64,
        spec.max_validators_per_withdrawals_sweep,
    );
    for _ in 0..bound {
        let validator = state.get_validator(validator_index as usize)?;
        let balance = *state.balances().get(validator_index as usize).ok_or(
            BeaconStateError::BalancesOutOfBounds(validator_index as usize),
        )?;
        if validator.is_fully_withdrawable_at(balance, epoch, spec, fork_name) {
            withdrawals.push(Withdrawal {
                index: withdrawal_index,
                validator_index,
                address: validator
                    .get_execution_withdrawal_address(spec)
                    .ok_or(BlockProcessingError::WithdrawalCredentialsInvalid)?,
                amount: balance,
            });
            withdrawal_index.safe_add_assign(1)?;
        } else if validator.is_partially_withdrawable_validator(balance, spec, fork_name) {
            withdrawals.push(Withdrawal {
                index: withdrawal_index,
                validator_index,
                address: validator
                    .get_execution_withdrawal_address(spec)
                    .ok_or(BlockProcessingError::WithdrawalCredentialsInvalid)?,
                amount: balance.safe_sub(
                    validator.get_max_effective_balance(spec, state.fork_name_unchecked()),
                )?,
            });
            withdrawal_index.safe_add_assign(1)?;
        }
        if withdrawals.len() == E::max_withdrawals_per_payload() {
            break;
        }
        validator_index = validator_index
            .safe_add(1)?
            .safe_rem(state.validators().len() as u64)?;
    }

    Ok((withdrawals.into(), partial_withdrawals_count))
}

pub fn process_execution_bid<E: EthSpec, Payload: AbstractExecPayload<E>>(
    state: &mut BeaconState<E>,
    block: BeaconBlockRef<'_, E, Payload>,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    if !state
        .fork_name(&spec)
        .map_err(BlockProcessingError::InconsistentStateFork)?
        .eip7732_enabled()
    {
        return Ok(());
    }

    let signed_bid = block.body().signed_execution_bid()?;
    if verify_signatures.is_true() {
        // Verify the bid signature
        block_verify!(
            execution_bid_signature_set(
                state,
                |i| get_pubkey_from_state(state, i),
                signed_bid,
                spec
            )?
            .verify(),
            ExecutionBidInvalid::BadSignature.into()
        );
    }

    let bid = &signed_bid.message;
    let builder_index = bid.builder_index;

    // Verify the bid is for the current slot
    block_verify!(
        bid.slot == state.slot(),
        ExecutionBidInvalid::SlotMismatch {
            state_slot: state.slot(),
            bid_slot: bid.slot,
        }
        .into()
    );
    // Verify the bid is for the correct parent block
    let state_block_hash = state.latest_block_hash()?;
    block_verify!(
        bid.parent_block_hash == state_block_hash,
        ExecutionBidInvalid::ParentBlockHashMismatch {
            state_block_hash,
            bid_parent_hash: bid.parent_block_hash,
        }
        .into()
    );
    let block_parent_root = block.parent_root();
    block_verify!(
        bid.parent_block_root == block_parent_root,
        ExecutionBidInvalid::ParentBlockRootMismatch {
            block_parent_root,
            bid_parent_root: bid.parent_block_root,
        }
        .into()
    );

    // Check the builder is active, non-slashed, and has funds to cover the bid
    let builder = state.get_validator(builder_index as usize)?;
    block_verify!(
        builder.is_active_at(state.current_epoch()),
        ExecutionBidInvalid::BuilderNotActive(builder_index).into()
    );
    block_verify!(
        !builder.slashed,
        ExecutionBidInvalid::BuilderSlashed(builder_index).into()
    );
    let builder_balance = state.get_balance(builder_index as usize)?;
    block_verify!(
        builder_balance >= bid.value,
        ExecutionBidInvalid::InsufficientBalance {
            builder_index,
            builder_balance,
            bid_value: bid.value,
        }
        .into()
    );

    // Transfer the funds from the builder to the proposer
    decrease_balance(state, builder_index as usize, bid.value)?;
    increase_balance(state, block.proposer_index() as usize, bid.value)?;

    *state.latest_execution_bid_eip7732_mut()? = bid.clone();

    Ok(())
}
