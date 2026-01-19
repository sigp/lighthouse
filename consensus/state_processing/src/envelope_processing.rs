use crate::BlockProcessingError;
use crate::VerifySignatures;
use crate::per_block_processing::compute_timestamp_at_slot;
use crate::per_block_processing::process_operations::{
    process_consolidation_requests, process_deposit_requests, process_withdrawal_requests,
};
use safe_arith::{ArithError, SafeArith};
use tree_hash::TreeHash;
use types::{
    BeaconState, BeaconStateError, BuilderPendingPayment, ChainSpec, EthSpec, ExecutionBlockHash,
    Hash256, SignedExecutionPayloadEnvelope, Slot,
};

// TODO(EIP-7732): don't use this redefinition..
macro_rules! envelope_verify {
    ($condition: expr, $result: expr) => {
        if !$condition {
            return Err($result);
        }
    };
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
    /// The withdrawals root doesn't match the state's latest withdrawals root
    WithdrawalsRootMismatch {
        state: Hash256,
        envelope: Hash256,
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
    /// The blob KZG commitments root doesn't match the committed bid
    BlobKzgCommitmentsRootMismatch {
        committed_bid: Hash256,
        envelope: Hash256,
    },
    // The previous randao didn't match the payload
    PrevRandaoMismatch {
        state: Hash256,
        envelope: Hash256,
    },
    // The timestamp didn't match the payload
    TimestampMismatch {
        state: u64,
        envelope: u64,
    },
    // Blob committments exceeded the maximum
    BlobLimitExceeded {
        max: usize,
        envelope: usize,
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
pub fn envelope_processing<E: EthSpec>(
    state: &mut BeaconState<E>,
    parent_state_root: Option<Hash256>,
    signed_envelope: &SignedExecutionPayloadEnvelope<E>,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<(), EnvelopeProcessingError> {
    if verify_signatures.is_true() {
        // Verify Signed Envelope Signature
        // TODO(EIP-7732): there is probably a more efficient way to do this..
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
    envelope_verify!(
        envelope.beacon_block_root == state.latest_block_header().tree_hash_root(),
        EnvelopeProcessingError::LatestBlockHeaderMismatch {
            envelope_root: envelope.beacon_block_root,
            block_header_root: state.latest_block_header().tree_hash_root(),
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
    // builder index match already verified
    if committed_bid.blob_kzg_commitments_root != envelope.blob_kzg_commitments.tree_hash_root() {
        return Err(EnvelopeProcessingError::BlobKzgCommitmentsRootMismatch {
            committed_bid: committed_bid.blob_kzg_commitments_root,
            envelope: envelope.blob_kzg_commitments.tree_hash_root(),
        });
    };

    // Verify the withdrawals root
    envelope_verify!(
        payload.withdrawals.tree_hash_root() == *state.latest_withdrawals_root()?,
        EnvelopeProcessingError::WithdrawalsRootMismatch {
            state: *state.latest_withdrawals_root()?,
            envelope: payload.withdrawals.tree_hash_root(),
        }
    );

    // Verify the gas limit
    envelope_verify!(
        payload.gas_limit == committed_bid.gas_limit,
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

    // Verify prev_randao
    envelope_verify!(
        payload.prev_randao == *state.get_randao_mix(state.current_epoch())?,
        EnvelopeProcessingError::PrevRandaoMismatch {
            state: *state.get_randao_mix(state.current_epoch())?,
            envelope: payload.prev_randao,
        }
    );

    // Verify the timestamp
    let state_timestamp = compute_timestamp_at_slot(state, state.slot(), spec)?;
    envelope_verify!(
        payload.timestamp == state_timestamp,
        EnvelopeProcessingError::TimestampMismatch {
            state: state_timestamp,
            envelope: payload.timestamp,
        }
    );

    // Verify the commitments are under limit
    let max_blobs = spec.max_blobs_per_block(state.current_epoch()) as usize;
    envelope_verify!(
        envelope.blob_kzg_commitments.len() <= max_blobs,
        EnvelopeProcessingError::BlobLimitExceeded {
            max: max_blobs,
            envelope: envelope.blob_kzg_commitments.len(),
        }
    );

    // process electra operations
    process_deposit_requests(state, &execution_requests.deposits, spec)?;
    process_withdrawal_requests(state, &execution_requests.withdrawals, spec)?;
    process_consolidation_requests(state, &execution_requests.consolidations, spec)?;

    // queue the builder payment
    let payment_index = E::slots_per_epoch()
        .safe_add(state.slot().as_u64().safe_rem(E::slots_per_epoch())?)?
        as usize;
    let mut payment = state
        .builder_pending_payments()?
        .get(payment_index)
        .ok_or(EnvelopeProcessingError::BuilderPaymentIndexOutOfBounds(
            payment_index,
        ))?
        .clone();
    let amount = payment.withdrawal.amount;
    if amount > 0 {
        let exit_queue_epoch = state.compute_exit_epoch_and_update_churn(amount, spec)?;
        payment.withdrawal.withdrawable_epoch =
            exit_queue_epoch.safe_add(spec.min_validator_withdrawability_delay)?;
        state
            .builder_pending_withdrawals_mut()?
            .push(payment.withdrawal)
            .map_err(|e| EnvelopeProcessingError::BeaconStateError(e.into()))?;
    }
    *state
        .builder_pending_payments_mut()?
        .get_mut(payment_index)
        .ok_or(EnvelopeProcessingError::BuilderPaymentIndexOutOfBounds(
            payment_index,
        ))? = BuilderPendingPayment::default();

    // cache the execution payload hash
    let availability_index = state
        .slot()
        .safe_rem(E::slots_per_historical_root() as u64)?
        .as_usize();
    state
        .execution_payload_availability_mut()?
        .set(availability_index, true)
        .map_err(EnvelopeProcessingError::BitFieldError)?;
    *state.latest_block_hash_mut()? = payload.block_hash;

    // verify the state root
    envelope_verify!(
        envelope.state_root == state.canonical_root()?,
        EnvelopeProcessingError::InvalidStateRoot {
            state: state.canonical_root()?,
            envelope: envelope.state_root,
        }
    );

    Ok(())
}
