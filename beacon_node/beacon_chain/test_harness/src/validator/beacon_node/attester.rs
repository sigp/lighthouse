use super::BenchingBeaconNode;
use attester::{BeaconNode as AttesterBeaconNode, BeaconNodeError as NodeError, PublishOutcome};
use beacon_chain::block_processing::Error as ProcessingError;
use beacon_chain::block_production::Error as BlockProductionError;
use db::ClientDB;
use slot_clock::SlotClock;
use types::{AttestationData, Signature};

impl<T: ClientDB, U: SlotClock> AttesterBeaconNode for BenchingBeaconNode<T, U>
where
    BlockProductionError: From<<U>::Error>,
    ProcessingError: From<<U as SlotClock>::Error>,
{
    fn produce_attestation_data(
        &self,
        slot: u64,
        shard: u64,
    ) -> Result<Option<AttestationData>, NodeError> {
        match self.beacon_chain.produce_attestation_data(slot, shard) {
            Ok(attestation_data) => Ok(Some(attestation_data)),
            Err(e) => Err(NodeError::RemoteFailure(format!("{:?}", e))),
        }
    }

    fn publish_attestation_data(
        &self,
        attestation_data: AttestationData,
        signature: Signature,
        validator_index: u64,
    ) -> Result<PublishOutcome, NodeError> {
        match self.beacon_chain.process_free_attestation(
            &attestation_data,
            &signature,
            validator_index,
        ) {
            Ok(_) => Ok(PublishOutcome::ValidAttestation),
            Err(e) => Err(NodeError::RemoteFailure(format!("{:?}", e))),
        }
    }
}
