use crate::beacon_chain::BeaconChain;
use bls::PublicKey;
use futures::Future;
use grpcio::{RpcContext, RpcStatus, RpcStatusCode, UnarySink};
use protos::services::{ActiveValidator, GetDutiesRequest, GetDutiesResponse, ValidatorDuty};
use protos::services_grpc::ValidatorService;
use slog::{debug, warn, Logger};
use ssz::Decodable;
use std::sync::Arc;
use types::{Epoch, RelativeEpoch};

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
    fn get_validator_duties(
        &mut self,
        ctx: RpcContext,
        req: GetDutiesRequest,
        sink: UnarySink<GetDutiesResponse>,
    ) {
        let validators = req.get_validators();
        debug!(self.log, "RPC request"; "endpoint" => "GetValidatorDuties", "epoch" => req.get_epoch());

        let epoch = Epoch::from(req.get_epoch());
        let mut resp = GetDutiesResponse::new();
        let resp_validators = resp.mut_active_validators();

        let spec = self.chain.get_spec();
        let state = self.chain.get_state();

        let relative_epoch =
            match RelativeEpoch::from_epoch(state.slot.epoch(spec.slots_per_epoch), epoch) {
                Ok(v) => v,
                Err(e) => {
                    // incorrect epoch
                    let log_clone = self.log.clone();
                    let f = sink
                        .fail(RpcStatus::new(
                            RpcStatusCode::FailedPrecondition,
                            Some(format!("Invalid epoch: {:?}", e)),
                        ))
                        .map_err(move |e| warn!(log_clone, "failed to reply {:?}: {:?}", req, e));
                    return ctx.spawn(f);
                }
            };

        let validator_proposers: Result<Vec<usize>, _> = epoch
            .slot_iter(spec.slots_per_epoch)
            .map(|slot| state.get_beacon_proposer_index(slot, relative_epoch, &spec))
            .collect();
        let validator_proposers = match validator_proposers {
            Ok(v) => v,
            Err(_) => {
                // could not get the validator proposer index
                let log_clone = self.log.clone();
                let f = sink
                    .fail(RpcStatus::new(
                        RpcStatusCode::InvalidArgument,
                        Some("Invalid public_key".to_string()),
                    ))
                    .map_err(move |e| warn!(log_clone, "failed to reply {:?} : {:?}", req, e));
                return ctx.spawn(f);
            }
        };

        // get the duties for each validator
        for validator_pk in validators.get_public_keys() {
            let mut active_validator = ActiveValidator::new();

            let public_key = match PublicKey::ssz_decode(validator_pk, 0) {
                Ok((v, _index)) => v,
                Err(_) => {
                    let log_clone = self.log.clone();
                    let f = sink
                        .fail(RpcStatus::new(
                            RpcStatusCode::InvalidArgument,
                            Some("Invalid public_key".to_string()),
                        ))
                        .map_err(move |e| warn!(log_clone, "failed to reply {:?}", req));
                    return ctx.spawn(f);
                }
            };

            // get the validator index
            let val_index = match state.get_validator_index(&public_key) {
                Ok(Some(index)) => index,
                Ok(None) => {
                    // index not present in registry, set the duties for this key to None
                    warn!(
                        self.log,
                        "RPC requested a public key that is not in the registry: {:?}", public_key
                    );
                    active_validator.set_none(false);
                    resp_validators.push(active_validator);
                    break;
                }
                // the cache is not built, throw an error
                Err(e) => {
                    let log_clone = self.log.clone();
                    let f = sink
                        .fail(RpcStatus::new(
                            RpcStatusCode::FailedPrecondition,
                            Some(format!("Beacon state error {:?}", e)),
                        ))
                        .map_err(move |e| warn!(log_clone, "Failed to reply {:?}: {:?}", req, e));
                    return ctx.spawn(f);
                }
            };

            // get attestation duties and check if validator is active
            let attestation_duties = match state.get_attestation_duties(val_index, &spec) {
                Ok(Some(v)) => v,
                Ok(_) => {
                    // validator is inactive, go to the next validator
                    warn!(
                        self.log,
                        "RPC requested an inactive validator key: {:?}", public_key
                    );
                    active_validator.set_none(false);
                    resp_validators.push(active_validator);
                    break;
                }
                // the cache is not built, throw an error
                Err(e) => {
                    let log_clone = self.log.clone();
                    let f = sink
                        .fail(RpcStatus::new(
                            RpcStatusCode::FailedPrecondition,
                            Some(format!("Beacon state error {:?}", e)),
                        ))
                        .map_err(move |e| warn!(log_clone, "Failed to reply {:?}: {:?}", req, e));
                    return ctx.spawn(f);
                }
            };

            // we have an active validator, set its duties
            let mut duty = ValidatorDuty::new();

            // check if the validator needs to propose a block
            if let Some(slot) = validator_proposers.iter().position(|&v| val_index == v) {
                duty.set_block_production_slot(
                    epoch.start_slot(spec.slots_per_epoch).as_u64() + slot as u64,
                );
            } else {
                // no blocks to propose this epoch
                duty.set_none(false)
            }

            duty.set_committee_index(attestation_duties.committee_index as u64);
            duty.set_attestation_slot(attestation_duties.slot.as_u64());
            duty.set_attestation_shard(attestation_duties.shard);

            active_validator.set_duty(duty);
            resp_validators.push(active_validator);
        }

        let f = sink
            .success(resp)
            .map_err(move |e| println!("failed to reply {:?}: {:?}", req, e));
        ctx.spawn(f)
    }
}
