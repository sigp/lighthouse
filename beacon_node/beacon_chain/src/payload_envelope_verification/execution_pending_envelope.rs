use task_executor::JoinHandle;
use types::{EthSpec, FullPayload};

use crate::{BeaconChainTypes, PayloadVerificationOutcome, payload_envelope_verification::PayloadEnvelopeImportData};


/// Used to await the result of executing payload with an EE.
pub type PayloadVerificationHandle<E: EthSpec> =
    JoinHandle<Option<Result<PayloadVerificationOutcome, FullPayload<E>>>>;

/// A wrapper around a `SignedBeaconBlock` that indicates that this block is fully verified and
/// ready to import into the `BeaconChain`. The validation includes:
///
/// - Parent is known
/// - Signatures
/// - State root check
/// - Block processing
///
/// Note: a `ExecutionPendingEnvelope` is not _forever_ valid to be imported, it may later become invalid
/// due to finality or some other event. A `ExecutionPendingEnvelope` should be imported into the
/// `BeaconChain` immediately after it is instantiated.
pub struct ExecutionPendingEnvelope<T: BeaconChainTypes> {
    pub block: MaybeAvailableBlock<T::EthSpec>,
    pub import_data: PayloadEnvelopeImportData<T::EthSpec>,
    pub payload_verification_handle: PayloadVerificationHandle<E>,
}