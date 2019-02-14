use super::traits::{BeaconNode, BeaconNodeError};
use super::EpochDuties;
use protos::services::{ProposeBlockSlotRequest, PublicKey as IndexRequest};
use protos::services_grpc::ValidatorServiceClient;
use ssz::ssz_encode;
use types::{Epoch, PublicKey, Slot};

impl BeaconNode for ValidatorServiceClient {
    /// Request the shuffling from the Beacon Node (BN).
    ///
    /// As this function takes a `PublicKey`, it will first attempt to resolve the public key into
    /// a validator index, then call the BN for production/attestation duties.
    ///
    /// Note: presently only block production information is returned.
    fn request_shuffling(
        &self,
        epoch: Epoch,
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
        req.set_epoch(epoch.as_u64());

        let reply = self
            .propose_block_slot(&req)
            .map_err(|err| BeaconNodeError::RemoteFailure(format!("{:?}", err)))?;

        let block_production_slot = if reply.has_slot() {
            Some(reply.get_slot())
        } else {
            None
        };

        let block_production_slot = match block_production_slot {
            Some(slot) => Some(Slot::new(slot)),
            None => None,
        };

        Ok(Some(EpochDuties {
            validator_index,
            block_production_slot,
        }))
    }
}
