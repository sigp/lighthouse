use bls::PublicKey;
use futures::Future;
use grpcio::{RpcContext, RpcStatus, RpcStatusCode, UnarySink};
use protos::services::{
    GetDutiesRequest, GetDutiesResponse, Validators};
use protos::services_grpc::ValidatorService;
use slog::{debug, Logger};
use ssz::Decodable;
use std::sync::Arc;
use crate::beacon_chain::BeaconChain;

#[derive(Clone)]
pub struct ValidatorServiceInstance {
    pub chain: Arc<BeaconChain>,
    pub log: Logger,
}
//TODO: Refactor Errors

impl ValidatorService for ValidatorServiceInstance {

    /// For a list of validator public keys, this function returns the slot at which each
    /// validator must propose a block, attest to a shard, their shard committee and the shard they
    /// need to attest to.
    fn get_validator_duties (
        &mut self,
        ctx: RpcContext,
        req: GetDutiesRequest,
        sink: UnarySink<GetDutiesResponse>,
    ) {
        let validators = req.get_validators();
        debug!(self.log, "RPC request"; "endpoint" => "GetValidatorDuties", "epoch" => req.get_epoch());

        let epoch = req.get_epoch();
        let mut resp = GetDutiesResponse::new();

        let spec = self.chain.spec;
        let state = self.chain.state.read();

        //TODO: Decide whether to rebuild the cache
        //TODO: Get the active validator indicies
        //let active_validator_indices = self.chain.state.read().get_cached_active_validator_indices(
        let active_validator_indices = &[1,2,3,4,5,6,7,8];
        // TODO: Is this the most efficient? Perhaps we cache this data structure.

        // this is an array of validators who are to propose this epoch
        // TODO: RelativeEpoch?
        let validator_proposers = 0..spec.slots_per_epoch.to_iter().map(|slot| state.get_beacon_proposer_index(slot, epoch, &spec)).collect();

        // get the duties for each validator
        for validator in validators {
            let active_validator = ActiveValidator::new();


        let public_key = match PublicKey::ssz_decode(validator, 0) {
            Ok((v_) => v,
            Err(_) => {
                let f = sink
                .fail(RpcStatus::new(
                    RpcStatusCode::InvalidArgument,
                    Some("Invalid public_key".to_string()),
                ))
                //TODO: Handle error correctly
                .map_err(move |e| println!("failed to reply {:?}: {:?}", req, e));
                return ctx.spawn(f);
            }
            };

            // is the validator active
            let val_index = match state.get_validator_index(&public_key) {
                Ok(index) => {
                    if active_validator_indices.contains(index) {
                        // validator is active, return the index
                        index
                    }
                    else {
                        // validator is inactive, go to the next validator
                        active_validator.set_none();
                        resp.push(active_validator);
                        break;
                    }
                },
                // the cache is not built, throw an error
                Err(_) =>{
                    let f = sink
                    .fail(RpcStatus::new(
                        RpcStatusCode::FailedPreCondition,
                        Some("Beacon state cache is not built".to_string()),
                    ))
                    //TODO: Handle error correctly
                    .map_err(move |e| println!("failed to reply {:?}: {:?}", req, e));
                    return ctx.spawn(f);
                }
            };

            // we have an active validator, set its duties
            let duty = ValidatorDuty::new();

            // check if it needs to propose a block
            let Some(slot) = validator_proposers.iter().position(|&v| val_index ==v) {
                duty.set_block_production_slot(slot);
            }
            else {
                // no blocks to propose this epoch
                duty.set_none()
            }

            // get attestation duties
            let attestation_duties = match state.get_attestation_duties(val_index, &spec) {
                Ok(v) => v,
                // the cache is not built, throw an error
                Err(_) =>{
                    let f = sink
                    .fail(RpcStatus::new(
                        RpcStatusCode::FailedPreCondition,
                        Some("Beacon state cache is not built".to_string()),
                    ))
                    //TODO: Handle error correctly
                    .map_err(move |e| println!("failed to reply {:?}: {:?}", req, e));
                    return ctx.spawn(f);
                }
            };

            duty.set_committee_index(attestation_duties.committee_index);
            duty.set_attestation_slot(attestation_duties.slot);
            duty.set_attestation_shard(attestation_duties.shard);

            active_validator.set_duty(duty);
            resp.push(active_validator);
            }


        let f = sink
            .success(resp)
            .map_err(move |e| println!("failed to reply {:?}: {:?}", req, e));
        ctx.spawn(f)
    }
}
