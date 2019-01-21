use super::traits::{BeaconNode, BeaconNodeError};
use super::EpochDuties;
use protos::services::{ProposeBlockSlotRequest, PublicKey as IndexRequest};
use protos::services_grpc::ValidatorServiceClient;
use ssz::ssz_encode;
use types::PublicKey;

impl BeaconNode for ValidatorServiceClient {
    fn request_shuffling(
        &self,
        epoch: u64,
        public_key: &PublicKey,
    ) -> Result<Option<EpochDuties>, BeaconNodeError> {
        // Lookup the validator index for the supplied public key.
        let validator_index = {
            let mut req = IndexRequest::new();
            req.set_public_key(ssz_encode(public_key).to_vec());
            let resp = self
                .validator_index(&req)
                .map_err(|err| BeaconNodeError::RemoteFailure(format!("{:?}", err)))?;
            resp.get_index()
        };

        let mut req = ProposeBlockSlotRequest::new();
        req.set_validator_index(validator_index);
        req.set_epoch(epoch);

        let reply = self
            .propose_block_slot(&req)
            .map_err(|err| BeaconNodeError::RemoteFailure(format!("{:?}", err)))?;

        let block_production_slot = if reply.has_slot() {
            Some(reply.get_slot())
        } else {
            None
        };

        Ok(Some(EpochDuties {
            validator_index,
            block_production_slot,
        }))
    }
}
