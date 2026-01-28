use std::sync::Arc;

use state_processing::ConsensusContext;
use types::{BeaconState, BlockImportSource, EthSpec, SignedExecutionPayloadEnvelope};

use crate::{PayloadVerificationOutcome, data_availability_checker_v2::AvailablePayload};

#[derive(Debug, PartialEq)]
pub struct PayloadImportData<E: EthSpec> {
    pub state: BeaconState<E>,
    pub consensus_context: ConsensusContext<E>,
}

/// A payload that has completed payload verification by an EL client but does not
/// have all requisite column data to get imported into fork choice.
pub struct AvailabilityPendingExecutedPayload<E: EthSpec> {
    pub payload: Arc<SignedExecutionPayloadEnvelope<E>>,
    pub import_data: PayloadImportData<E>,
    pub payload_verification_outcome: PayloadVerificationOutcome,
}

impl<E: EthSpec> AvailabilityPendingExecutedPayload<E> {
    pub fn new(
        payload: Arc<SignedExecutionPayloadEnvelope<E>>,
        import_data: PayloadImportData<E>,
        payload_verification_outcome: PayloadVerificationOutcome,
    ) -> Self {
        Self {
            payload,
            import_data,
            payload_verification_outcome,
        }
    }

    pub fn as_payload(&self) -> &SignedExecutionPayloadEnvelope<E> {
        &self.payload
    }

    pub fn num_blobs_expected(&self) -> usize {
        self.payload.message.blob_kzg_commitments.len()
    }
}

/// A payload that has completed all payload verification by an EL client
/// **and** has all requisite column data to be imported into fork choice.
pub struct AvailableExecutedPayload<E: EthSpec> {
    pub payload: AvailablePayload<E>,
    pub import_data: PayloadImportData<E>,
    pub payload_verification_outcome: PayloadVerificationOutcome,
}

impl<E: EthSpec> AvailableExecutedPayload<E> {
    pub fn new(
        payload: AvailablePayload<E>,
        import_data: PayloadImportData<E>,
        payload_verification_outcome: PayloadVerificationOutcome,
    ) -> Self {
        Self {
            payload,
            import_data,
            payload_verification_outcome,
        }
    }
}

pub enum PayloadProcessStatus<E: EthSpec> {
    /// Payload is not in any pre-import cache. Payload may be in the data-base or in the fork-choice.
    Unknown,
    /// Payload is currently processing but not yet validated.
    NotValidated(Arc<SignedExecutionPayloadEnvelope<E>>, BlockImportSource),
    /// Payload is fully valid, but not yet imported. It's cached in the da_checker while awaiting
    /// columns.
    ExecutionValidated(Arc<SignedExecutionPayloadEnvelope<E>>),
}
