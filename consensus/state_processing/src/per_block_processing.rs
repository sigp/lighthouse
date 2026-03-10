use crate::consensus_context::ConsensusContext;
use errors::{
    BlockOperationError, BlockProcessingError, ExecutionPayloadBidInvalid, HeaderInvalid,
};
use rayon::prelude::*;
use safe_arith::{ArithError, SafeArith};
use signature_sets::{
    block_proposal_signature_set, execution_payload_bid_signature_set,
    get_builder_pubkey_from_state, get_pubkey_from_state, randao_signature_set,
};
use std::borrow::Cow;
use tree_hash::TreeHash;
use typenum::Unsigned;
use types::{consts::gloas::BUILDER_INDEX_SELF_BUILD, *};

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
pub use withdrawals::get_expected_withdrawals;

pub mod altair;
pub mod block_signature_verifier;
pub mod builder;
pub mod deneb;
pub mod errors;
mod is_valid_indexed_attestation;
mod is_valid_indexed_payload_attestation;
pub mod process_operations;
pub mod signature_sets;
pub mod tests;
mod verify_attestation;
mod verify_attester_slashing;
mod verify_bls_to_execution_change;
mod verify_deposit;
mod verify_exit;
mod verify_payload_attestation;
mod verify_proposer_slashing;
pub mod withdrawals;

use crate::common::update_progressive_balances_cache::{
    initialize_progressive_balances_cache, update_progressive_balances_metrics,
};
use crate::epoch_cache::initialize_epoch_cache;
#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
use tracing::instrument;

/// The strategy to be used when validating the block's signatures.
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
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
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
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
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
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
            withdrawals::gloas::process_withdrawals::<E>(state, spec)?;
            process_execution_payload_bid(state, block, verify_signatures, spec)?;
        } else {
            if state.fork_name_unchecked().capella_enabled() {
                withdrawals::capella_electra::process_withdrawals::<E, Payload>(
                    state,
                    body.execution_payload()?,
                    spec,
                )?;
            }
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
        .safe_mul(spec.get_slot_duration().as_secs())
        .and_then(|since_genesis| state.genesis_time().safe_add(since_genesis))
}

pub fn can_builder_cover_bid<E: EthSpec>(
    state: &BeaconState<E>,
    builder_index: BuilderIndex,
    builder: &Builder,
    bid_amount: u64,
    spec: &ChainSpec,
) -> Result<bool, BlockProcessingError> {
    let builder_balance = builder.balance;
    let pending_withdrawals_amount =
        state.get_pending_balance_to_withdraw_for_builder(builder_index)?;
    let min_balance = spec
        .min_deposit_amount
        .safe_add(pending_withdrawals_amount)?;
    if builder_balance < min_balance {
        Ok(false)
    } else {
        Ok(builder_balance.safe_sub(min_balance)? >= bid_amount)
    }
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

    // For self-builds, amount must be zero regardless of withdrawal credential prefix
    if builder_index == BUILDER_INDEX_SELF_BUILD {
        block_verify!(
            amount == 0,
            ExecutionPayloadBidInvalid::SelfBuildNonZeroAmount.into()
        );
        block_verify!(
            signed_bid.signature.is_infinity(),
            ExecutionPayloadBidInvalid::BadSignature.into()
        );
    } else {
        let builder = state.get_builder(builder_index)?;

        // Verify that the builder is active
        block_verify!(
            builder.is_active_at_finalized_epoch(state.finalized_checkpoint().epoch, spec),
            ExecutionPayloadBidInvalid::BuilderNotActive(builder_index).into()
        );

        // Verify that the builder has funds to cover the bid
        block_verify!(
            can_builder_cover_bid(state, builder_index, builder, amount, spec)?,
            ExecutionPayloadBidInvalid::InsufficientBalance {
                builder_index,
                builder_balance: builder.balance,
                bid_value: amount,
            }
            .into()
        );

        if verify_signatures.is_true() {
            block_verify!(
                // We know this is NOT a self-build, so there MUST be a signature set (func does not
                // return None).
                execution_payload_bid_signature_set(
                    state,
                    |i| get_builder_pubkey_from_state(state, i),
                    signed_bid,
                    spec
                )?
                .ok_or(ExecutionPayloadBidInvalid::BadSignature)?
                .verify(),
                ExecutionPayloadBidInvalid::BadSignature.into()
            );
        }
    }

    // Verify commitments are under limit
    let max_blobs_per_block = spec.max_blobs_per_block(state.current_epoch()) as usize;
    block_verify!(
        bid.blob_kzg_commitments.len() <= max_blobs_per_block,
        ExecutionPayloadBidInvalid::ExcessBlobCommitments {
            max: max_blobs_per_block,
            bid: bid.blob_kzg_commitments.len(),
        }
        .into()
    );

    // Verify that the bid is for the current slot
    block_verify!(
        bid.slot == block.slot(),
        ExecutionPayloadBidInvalid::SlotMismatch {
            bid_slot: bid.slot,
            block_slot: block.slot(),
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

    let expected_randao = *state.get_randao_mix(state.current_epoch())?;
    block_verify!(
        bid.prev_randao == expected_randao,
        ExecutionPayloadBidInvalid::PrevRandaoMismatch {
            expected: expected_randao,
            bid: bid.prev_randao,
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

        let payment_index = E::SlotsPerEpoch::to_usize()
            .safe_add(bid.slot.as_usize().safe_rem(E::SlotsPerEpoch::to_usize())?)?;

        *state
            .builder_pending_payments_mut()?
            .get_mut(payment_index)
            .ok_or(BlockProcessingError::BeaconStateError(
                BeaconStateError::InvalidBuilderPendingPaymentsIndex(payment_index),
            ))? = pending_payment;
    }

    // Cache the execution bid
    *state.latest_execution_payload_bid_mut()? = bid.clone();

    Ok(())
}
