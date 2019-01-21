use super::traits::{BeaconNode, BeaconNodeError};
use super::EpochDuties;
use protos::services::ValidatorAssignmentRequest;
use protos::services_grpc::ValidatorServiceClient;
use ssz::ssz_encode;
use types::PublicKey;

impl BeaconNode for ValidatorServiceClient {
    fn request_shuffling(
        &self,
        epoch: u64,
        public_key: &PublicKey,
    ) -> Result<Option<EpochDuties>, BeaconNodeError> {
        let mut req = ValidatorAssignmentRequest::new();
        req.set_epoch(epoch);
        req.set_public_key(ssz_encode(public_key).to_vec());

        let reply = self
            .validator_assignment(&req)
            .map_err(|err| BeaconNodeError::RemoteFailure(format!("{:?}", err)))?;

        if reply.has_validator_assignment() {
            let assignment = reply.get_validator_assignment();

            let block_production_slot = if assignment.has_block_production_slot() {
                Some(assignment.get_block_production_slot())
            } else {
                None
            };

            let duties = EpochDuties {
                block_production_slot,
            };

            Ok(Some(duties))
        } else {
            Ok(None)
        }
    }
}
