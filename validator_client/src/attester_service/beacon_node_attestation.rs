//TODO: generalise these enums to the crate
use super::block_producer::{BeaconNodeError, PublishOutcome};

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
    fn publish_attestation(
        &self,
        attestation: Attestation,
    ) -> Result<PublishOutcome, BeaconNodeError>;
}
