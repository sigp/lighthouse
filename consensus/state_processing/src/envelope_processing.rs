use crate::VerifySignatures;
use crate::per_block_processing::compute_timestamp_at_slot;
use safe_arith::ArithError;
use tree_hash::TreeHash;
use types::{
    BeaconState, BeaconStateError, BuilderIndex, ChainSpec, EthSpec, ExecutionBlockHash, Hash256,
    SignedExecutionPayloadEnvelope, Slot,
};

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
    // The execution requests root doesn't match the committed bid
    ExecutionRequestsRootMismatch {
        committed_bid: Hash256,
        envelope: Hash256,
    },
    /// The envelope was deemed invalid by the execution engine.
    ExecutionInvalid,
}

impl From<BeaconStateError> for EnvelopeProcessingError {
    fn from(e: BeaconStateError) -> Self {
        EnvelopeProcessingError::BeaconStateError(e)
    }
}

impl From<ArithError> for EnvelopeProcessingError {
    fn from(e: ArithError) -> Self {
        EnvelopeProcessingError::ArithError(e)
    }
}

/// Verifies a `SignedExecutionPayloadEnvelope` against the beacon state.
///
/// This function performs pure verification with no state mutation. The execution requests
/// from the envelope are deferred to be processed in the next block via
/// `process_parent_execution_payload`.
///
/// `block_state_root` should be the post-block state root (used to fill in the block header
/// for beacon_block_root verification). If `None`, the latest_block_header must already have
/// its state_root filled in.
pub fn verify_execution_payload_envelope<E: EthSpec>(
    state: &BeaconState<E>,
    signed_envelope: &SignedExecutionPayloadEnvelope<E>,
    verify_signatures: VerifySignatures,
    block_state_root: Hash256,
    spec: &ChainSpec,
) -> Result<(), EnvelopeProcessingError> {
    if verify_signatures.is_true() && !signed_envelope.verify_signature_with_state(state, spec)? {
        return Err(EnvelopeProcessingError::BadSignature);
    }

    let envelope = &signed_envelope.message;
    let payload = &envelope.payload;

    // Verify consistency with the beacon block.
    // Use a copy of the header with state_root filled in, matching the spec's approach.
    let mut header = state.latest_block_header().clone();
    if header.state_root == Hash256::default() {
        // The caller must provide the post-block state root so we can compute
        // the block header root without mutating state.
        header.state_root = block_state_root;
    }
    let latest_block_header_root = header.tree_hash_root();
    envelope_verify!(
        envelope.beacon_block_root == latest_block_header_root,
        EnvelopeProcessingError::LatestBlockHeaderMismatch {
            envelope_root: envelope.beacon_block_root,
            block_header_root: latest_block_header_root,
        }
    );
    envelope_verify!(
        envelope.slot() == state.slot(),
        EnvelopeProcessingError::SlotMismatch {
            envelope_slot: envelope.slot(),
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

    // Verify execution requests root matches committed bid
    let execution_requests_root = envelope.execution_requests.tree_hash_root();
    envelope_verify!(
        execution_requests_root == committed_bid.execution_requests_root,
        EnvelopeProcessingError::ExecutionRequestsRootMismatch {
            committed_bid: committed_bid.execution_requests_root,
            envelope: execution_requests_root,
        }
    );

    // TODO(gloas): newPayload happens here in the spec, ensure we wire that up correctly

    Ok(())
}
