use crate::BlockProcessingError;
use crate::VerifySignatures;
use crate::per_block_processing::compute_timestamp_at_slot;
use crate::per_block_processing::process_operations::{
    process_consolidation_requests, process_deposit_requests_post_gloas,
    process_withdrawal_requests,
};
use safe_arith::{ArithError, SafeArith};
use tree_hash::TreeHash;
use types::{
    BeaconState, BeaconStateError, BuilderIndex, BuilderPendingPayment, ChainSpec, EthSpec,
    ExecutionBlockHash, Hash256, SignedExecutionPayloadEnvelope, Slot,
};

macro_rules! envelope_verify {
    ($condition: expr, $result: expr) => {
        if !$condition {
            return Err($result);
        }
    };
}

/// The strategy to be used when validating the payloads state root.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(PartialEq, Clone, Copy)]
pub enum VerifyStateRoot {
    /// Validate state root.
    True,
    /// Do not validate state root. Use with caution.
    /// This should only be used when first constructing the payload envelope.
    False,
}

impl VerifyStateRoot {
    pub fn is_true(self) -> bool {
        self == VerifyStateRoot::True
    }
}

#[derive(Debug, Clone)]
pub enum EnvelopeProcessingError {
    /// Bad Signature
    BadSignature,
    BeaconStateError(BeaconStateError),
    BlockProcessingError(BlockProcessingError),
    ArithError(ArithError),
    /// Envelope doesn't match latest beacon block header
    LatestBlockHeaderMismatch {
        envelope_root: Hash256,
        block_header_root: Hash256,
    },
    /// Envelope doesn't match latest beacon block slot
    SlotMismatch {
        envelope_slot: Slot,
        parent_state_slot: Slot,
    },
    /// The payload withdrawals don't match the state's payload withdrawals.
    WithdrawalsRootMismatch {
        state: Hash256,
        payload: Hash256,
    },
    // The builder index doesn't match the committed bid.
    BuilderIndexMismatch {
        committed_bid: BuilderIndex,
        envelope: BuilderIndex,
    },
    // The gas limit doesn't match the committed bid
    GasLimitMismatch {
        committed_bid: u64,
        envelope: u64,
    },
    // The block hash doesn't match the committed bid
    BlockHashMismatch {
        committed_bid: ExecutionBlockHash,
        envelope: ExecutionBlockHash,
    },
    // The parent hash doesn't match the previous execution payload
    ParentHashMismatch {
        state: ExecutionBlockHash,
        envelope: ExecutionBlockHash,
    },
    // The previous randao didn't match the payload
    PrevRandaoMismatch {
        committed_bid: Hash256,
        envelope: Hash256,
    },
    // The timestamp didn't match the payload
    TimestampMismatch {
        state: u64,
        envelope: u64,
    },
    // Invalid state root
    InvalidStateRoot {
        state: Hash256,
        envelope: Hash256,
    },
    // BitFieldError
    BitFieldError(ssz::BitfieldError),
    // Some kind of error calculating the builder payment index
    BuilderPaymentIndexOutOfBounds(usize),
    /// The envelope was deemed invalid by the execution engine.
    ExecutionInvalid,
}

impl From<BeaconStateError> for EnvelopeProcessingError {
    fn from(e: BeaconStateError) -> Self {
        EnvelopeProcessingError::BeaconStateError(e)
    }
}

impl From<BlockProcessingError> for EnvelopeProcessingError {
    fn from(e: BlockProcessingError) -> Self {
        EnvelopeProcessingError::BlockProcessingError(e)
    }
}

impl From<ArithError> for EnvelopeProcessingError {
    fn from(e: ArithError) -> Self {
        EnvelopeProcessingError::ArithError(e)
    }
}

/// Processes a `SignedExecutionPayloadEnvelope`
///
/// This function does all the state modifications inside `process_execution_payload()`
pub fn process_execution_payload_envelope<E: EthSpec>(
    state: &mut BeaconState<E>,
    parent_state_root: Option<Hash256>,
    signed_envelope: &SignedExecutionPayloadEnvelope<E>,
    verify_signatures: VerifySignatures,
    verify_state_root: VerifyStateRoot,
    spec: &ChainSpec,
) -> Result<(), EnvelopeProcessingError> {
    if verify_signatures.is_true() {
        // Verify Signed Envelope Signature
        if !signed_envelope.verify_signature_with_state(state, spec)? {
            return Err(EnvelopeProcessingError::BadSignature);
        }
    }

    let envelope = &signed_envelope.message;
    let payload = &envelope.payload;
    let execution_requests = &envelope.execution_requests;

    // Cache latest block header state root
    if state.latest_block_header().state_root == Hash256::default() {
        let previous_state_root = parent_state_root
            .map(Ok)
            .unwrap_or_else(|| state.canonical_root())?;
        state.latest_block_header_mut().state_root = previous_state_root;
    }

    // Verify consistency with the beacon block
    let latest_block_header_root = state.latest_block_header().tree_hash_root();
    envelope_verify!(
        envelope.beacon_block_root == latest_block_header_root,
        EnvelopeProcessingError::LatestBlockHeaderMismatch {
            envelope_root: envelope.beacon_block_root,
            block_header_root: latest_block_header_root,
        }
    );
    envelope_verify!(
        envelope.slot == state.slot(),
        EnvelopeProcessingError::SlotMismatch {
            envelope_slot: envelope.slot,
            parent_state_slot: state.slot(),
        }
    );

    // Verify consistency with the committed bid
    let committed_bid = state.latest_execution_payload_bid()?;
    envelope_verify!(
        envelope.builder_index == committed_bid.builder_index,
        EnvelopeProcessingError::BuilderIndexMismatch {
            committed_bid: committed_bid.builder_index,
            envelope: envelope.builder_index,
        }
    );
    envelope_verify!(
        committed_bid.prev_randao == payload.prev_randao,
        EnvelopeProcessingError::PrevRandaoMismatch {
            committed_bid: committed_bid.prev_randao,
            envelope: payload.prev_randao,
        }
    );

    // Verify consistency with expected withdrawals
    // NOTE: we don't bother hashing here except in case of error, because we can just compare for
    // equality directly. This equality check could be more straight-forward if the types were
    // changed to match (currently we are comparing VariableList to List). This could happen
    // coincidentally when we adopt ProgressiveList.
    envelope_verify!(
        payload.withdrawals.len() == state.payload_expected_withdrawals()?.len()
            && payload
                .withdrawals
                .iter()
                .eq(state.payload_expected_withdrawals()?.iter()),
        EnvelopeProcessingError::WithdrawalsRootMismatch {
            state: state.payload_expected_withdrawals()?.tree_hash_root(),
            payload: payload.withdrawals.tree_hash_root(),
        }
    );

    // Verify the gas limit
    envelope_verify!(
        committed_bid.gas_limit == payload.gas_limit,
        EnvelopeProcessingError::GasLimitMismatch {
            committed_bid: committed_bid.gas_limit,
            envelope: payload.gas_limit,
        }
    );

    // Verify the block hash
    envelope_verify!(
        committed_bid.block_hash == payload.block_hash,
        EnvelopeProcessingError::BlockHashMismatch {
            committed_bid: committed_bid.block_hash,
            envelope: payload.block_hash,
        }
    );

    // Verify consistency of the parent hash with respect to the previous execution payload
    envelope_verify!(
        payload.parent_hash == *state.latest_block_hash()?,
        EnvelopeProcessingError::ParentHashMismatch {
            state: *state.latest_block_hash()?,
            envelope: payload.parent_hash,
        }
    );

    // Verify timestamp
    let state_timestamp = compute_timestamp_at_slot(state, state.slot(), spec)?;
    envelope_verify!(
        payload.timestamp == state_timestamp,
        EnvelopeProcessingError::TimestampMismatch {
            state: state_timestamp,
            envelope: payload.timestamp,
        }
    );

    // TODO(gloas): newPayload happens here in the spec, ensure we wire that up correctly

    process_deposit_requests_post_gloas(state, &execution_requests.deposits, spec)?;
    process_withdrawal_requests(state, &execution_requests.withdrawals, spec)?;
    process_consolidation_requests(state, &execution_requests.consolidations, spec)?;

    // Queue the builder payment
    let payment_index = E::slots_per_epoch()
        .safe_add(state.slot().as_u64().safe_rem(E::slots_per_epoch())?)?
        as usize;
    let payment_mut = state
        .builder_pending_payments_mut()?
        .get_mut(payment_index)
        .ok_or(EnvelopeProcessingError::BuilderPaymentIndexOutOfBounds(
            payment_index,
        ))?;

    // We have re-ordered the blanking out of the pending payment to avoid a double-lookup.
    // This is semantically equivalent to the ordering used by the spec because we have taken a
    // clone of the payment prior to doing the write.
    let payment_withdrawal = payment_mut.withdrawal.clone();
    *payment_mut = BuilderPendingPayment::default();

    let amount = payment_withdrawal.amount;
    if amount > 0 {
        state
            .builder_pending_withdrawals_mut()?
            .push(payment_withdrawal)
            .map_err(|e| EnvelopeProcessingError::BeaconStateError(e.into()))?;
    }

    // Cache the execution payload hash
    let availability_index = state
        .slot()
        .as_usize()
        .safe_rem(E::slots_per_historical_root())?;
    state
        .execution_payload_availability_mut()?
        .set(availability_index, true)
        .map_err(EnvelopeProcessingError::BitFieldError)?;
    *state.latest_block_hash_mut()? = payload.block_hash;

    if verify_state_root.is_true() {
        // Verify the state root
        let state_root = state.canonical_root()?;
        envelope_verify!(
            envelope.state_root == state_root,
            EnvelopeProcessingError::InvalidStateRoot {
                state: state_root,
                envelope: envelope.state_root,
            }
        );
    }

    Ok(())
}
