use super::epoch_duties::{EpochDuties, EpochDuty};
use super::traits::{BeaconNode, BeaconNodeError};
use grpcio::CallOption;
use protos::services::{GetDutiesRequest, Validators};
use protos::services_grpc::ValidatorServiceClient;
use ssz::ssz_encode;
use std::collections::HashMap;
use std::time::Duration;
use types::{Epoch, Keypair, Slot};

impl BeaconNode for ValidatorServiceClient {
    /// Requests all duties (block signing and committee attesting) from the Beacon Node (BN).
    fn request_duties(
        &self,
        epoch: Epoch,
        signers: &[Keypair],
    ) -> Result<EpochDuties, BeaconNodeError> {
        // Get the required duties from all validators
        // build the request
        let mut req = GetDutiesRequest::new();
        req.set_epoch(epoch.as_u64());
        let mut validators = Validators::new();
        validators.set_public_keys(signers.iter().map(|v| ssz_encode(&v.pk)).collect());
        req.set_validators(validators);

        // set a timeout for requests
        // let call_opt = CallOption::default().timeout(Duration::from_secs(2));

        // send the request, get the duties reply
        let reply = self
            .get_validator_duties(&req)
            .map_err(|err| BeaconNodeError::RemoteFailure(format!("{:?}", err)))?;

        let mut epoch_duties: HashMap<Keypair, Option<EpochDuty>> = HashMap::new();
        for (index, validator_duty) in reply.get_active_validators().iter().enumerate() {
            if !validator_duty.has_duty() {
                // validator is inactive
                epoch_duties.insert(signers[index].clone(), None);
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
                validator_index: active_duty.get_validator_index(),
            };
            epoch_duties.insert(signers[index].clone(), Some(epoch_duty));
        }
        Ok(epoch_duties)
    }
}
