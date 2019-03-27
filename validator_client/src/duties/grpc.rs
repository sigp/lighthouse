use super::epoch_duties::{EpochDuties, EpochDuty};
use super::traits::{BeaconNode, BeaconNodeError};
use protos::services::{
    ActiveValidator, GetDutiesRequest, GetDutiesResponse, ValidatorDuty, Validators,
};
use protos::services_grpc::ValidatorServiceClient;
use ssz::ssz_encode;
use std::collections::HashMap;
use types::{Epoch, PublicKey, Slot};

impl BeaconNode for ValidatorServiceClient {
    /// Requests all duties (block signing and committee attesting) from the Beacon Node (BN).
    fn request_duties(
        &self,
        epoch: Epoch,
        pubkeys: &[PublicKey],
    ) -> Result<EpochDuties, BeaconNodeError> {
        // Get the required duties from all validators
        // build the request
        let mut req = GetDutiesRequest::new();
        req.set_epoch(epoch.as_u64());
        let validators = Validators::new().mut_public_key();
        for pubkey in pubkeys {
            validators.push(pubkey);
        }
        req.set_validators(validators);

        // send the request, get the duties reply
        let reply = self
            .get_validator_duties(&req)
            .map_err(|err| BeaconNodeError::RemoteFailure(format!("{:?}", err)))?;

        let mut epoch_duties: HashMap<PublicKey, Option<EpochDuties>> = HashMap::new();
        for (index, validator_duty) in reply.get_active_validator().enumerate() {
            if let Some(duty) = validator_duty.has_slot() {
                // the validator is active
                //build the EpochDuty
                let active_duty = duty.get_duty();
                let block_produce_slot = active_duty.get_block_produce_slot();
                let epoch_duty = EpochDuty {
                    block_produce_slot,
                    committee_slot: active_duty.get_committee_slot(),
                    committee_shard: active_duty.get_committee_shard(),
                    committee_index: active_duty.get_committee_index(),
                };
                epoch_duties.insert(pubkeys[index], Some(epoch_duty));
            } else {
                // validator is not active and has no duties
                epoch_duties.insert(pubkeys[index], None);
            }
        }
        Ok(epoch_duties)
    }
}
