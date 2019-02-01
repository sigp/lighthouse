use super::BenchingBeaconNode;
use attester::{BeaconNode as AttesterBeaconNode, BeaconNodeError as NodeError, PublishOutcome};
use beacon_chain::block_processing::Error as ProcessingError;
use beacon_chain::block_production::Error as BlockProductionError;
use db::ClientDB;
use slot_clock::SlotClock;
use types::{AttestationData, FreeAttestation};

impl<T: ClientDB, U: SlotClock> AttesterBeaconNode for BenchingBeaconNode<T, U>
where
    BlockProductionError: From<<U>::Error>,
    ProcessingError: From<<U as SlotClock>::Error>,
{
    fn produce_attestation_data(
        &self,
        _slot: u64,
        shard: u64,
    ) -> Result<Option<AttestationData>, NodeError> {
        match self.beacon_chain.produce_attestation_data(shard) {
            Ok(attestation_data) => Ok(Some(attestation_data)),
            Err(e) => Err(NodeError::RemoteFailure(format!("{:?}", e))),
        }
    }

    fn publish_attestation_data(
        &self,
        free_attestation: FreeAttestation,
    ) -> Result<PublishOutcome, NodeError> {
        self.published_attestations.write().push(free_attestation);
        Ok(PublishOutcome::ValidAttestation)
    }
}
