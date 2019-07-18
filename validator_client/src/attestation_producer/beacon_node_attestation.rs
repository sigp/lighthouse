//TODO: generalise these enums to the crate
use crate::block_producer::{BeaconNodeError, PublishOutcome};
use types::{Attestation, AttestationData, EthSpec, Slot};

/// Defines the methods required to produce and publish attestations on a Beacon Node. Abstracts the
/// actual beacon node.
pub trait BeaconNodeAttestation: Send + Sync {
    /// Request that the node produces the required attestation data.
    ///
    fn produce_attestation_data(
        &self,
        slot: Slot,
        shard: u64,
    ) -> Result<AttestationData, BeaconNodeError>;

    /// Request that the node publishes a attestation.
    ///
    /// Returns `true` if the publish was successful.
    fn publish_attestation<T: EthSpec>(
        &self,
        attestation: Attestation<T>,
    ) -> Result<PublishOutcome, BeaconNodeError>;
}
