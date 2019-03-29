use super::beacon_node_duties::{BeaconNodeDuties, BeaconNodeDutiesError};
use super::epoch_duties::{EpochDuties, EpochDuty};
use grpcio::CallOption;
use protos::services::{GetDutiesRequest, Validators};
use protos::services_grpc::ValidatorServiceClient;
use ssz::ssz_encode;
use std::collections::HashMap;
use std::time::Duration;
use types::{Epoch, PublicKey, Slot};

impl BeaconNodeDuties for ValidatorServiceClient {
    /// Requests all duties (block signing and committee attesting) from the Beacon Node (BN).
    fn request_duties(
        &self,
        epoch: Epoch,
        pubkeys: &[PublicKey],
    ) -> Result<EpochDuties, BeaconNodeDutiesError> {
        // Get the required duties from all validators
        // build the request
        let mut req = GetDutiesRequest::new();
        req.set_epoch(epoch.as_u64());
        let mut validators = Validators::new();
        validators.set_public_keys(pubkeys.iter().map(|v| ssz_encode(v)).collect());
        req.set_validators(validators);

        // set a timeout for requests
        // let call_opt = CallOption::default().timeout(Duration::from_secs(2));

        // send the request, get the duties reply
        let reply = self
            .get_validator_duties(&req)
            .map_err(|err| BeaconNodeDutiesError::RemoteFailure(format!("{:?}", err)))?;

        let mut epoch_duties: HashMap<PublicKey, Option<EpochDuty>> = HashMap::new();
        for (index, validator_duty) in reply.get_active_validators().iter().enumerate() {
            if !validator_duty.has_duty() {
                // validator is inactive
                epoch_duties.insert(pubkeys[index].clone(), None);
                continue;
            }
            // active validator
            let active_duty = validator_duty.get_duty();
            let block_production_slot = {
                if active_duty.has_block_production_slot() {
                    Some(Slot::from(active_duty.get_block_production_slot()))
                } else {
                    None
                }
            };
            let epoch_duty = EpochDuty {
                block_production_slot,
                attestation_slot: Slot::from(active_duty.get_attestation_slot()),
                attestation_shard: active_duty.get_attestation_shard(),
                committee_index: active_duty.get_committee_index(),
            };
            epoch_duties.insert(pubkeys[index].clone(), Some(epoch_duty));
        }
        Ok(epoch_duties)
    }
}
