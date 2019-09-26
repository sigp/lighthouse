use beacon_chain::{BeaconChain, BeaconChainTypes};
use bls::PublicKey;
use futures::Future;
use grpcio::{RpcContext, RpcStatus, RpcStatusCode, UnarySink};
use protos::services::{ActiveValidator, GetDutiesRequest, GetDutiesResponse, ValidatorDuty};
use protos::services_grpc::ValidatorService;
use slog::{trace, warn};
use ssz::Decode;
use std::sync::Arc;
use types::{Epoch, EthSpec, RelativeEpoch};

#[derive(Clone)]
pub struct ValidatorServiceInstance<T: BeaconChainTypes> {
    pub chain: Arc<BeaconChain<T>>,
    pub log: slog::Logger,
}

impl<T: BeaconChainTypes> ValidatorService for ValidatorServiceInstance<T> {
    /// For a list of validator public keys, this function returns the slot at which each
    /// validator must propose a block, attest to a shard, their shard committee and the shard they
    /// need to attest to.
    fn get_validator_duties(
        &mut self,
        ctx: RpcContext,
        req: GetDutiesRequest,
        sink: UnarySink<GetDutiesResponse>,
    ) {
        trace!(self.log, "RPC request"; "endpoint" => "GetValidatorDuties", "epoch" => req.get_epoch());
        let validators = req.get_validators();

        let epoch = Epoch::from(req.get_epoch());
        let slot = epoch.start_slot(T::EthSpec::slots_per_epoch());

        let mut state = if let Ok(state) = self.chain.state_at_slot(slot) {
            state.clone()
        } else {
            let log_clone = self.log.clone();
            let f = sink
                .fail(RpcStatus::new(
                    RpcStatusCode::FailedPrecondition,
                    Some("No state".to_string()),
                ))
                .map_err(move |e| warn!(log_clone, "failed to reply {:?}: {:?}", req, e));
            return ctx.spawn(f);
        };

        let _ = state.build_all_caches(&self.chain.spec);

        assert_eq!(
            state.current_epoch(),
            epoch,
            "Retrieved state should be from the same epoch"
        );

        let mut resp = GetDutiesResponse::new();
        let resp_validators = resp.mut_active_validators();

        let validator_proposers: Result<Vec<usize>, _> = epoch
            .slot_iter(T::EthSpec::slots_per_epoch())
            .map(|slot| {
                state.get_beacon_proposer_index(slot, RelativeEpoch::Current, &self.chain.spec)
            })
            .collect();
        let validator_proposers = match validator_proposers {
            Ok(v) => v,
            Err(e) => {
                // could not get the validator proposer index
                let log_clone = self.log.clone();
                let f = sink
                    .fail(RpcStatus::new(
                        RpcStatusCode::FailedPrecondition,
                        Some(format!("Could not find beacon proposers: {:?}", e)),
                    ))
                    .map_err(move |e| warn!(log_clone, "failed to reply {:?} : {:?}", req, e));
                return ctx.spawn(f);
            }
        };

        // get the duties for each validator
        for validator_pk in validators.get_public_keys() {
            let mut active_validator = ActiveValidator::new();

            let public_key = match PublicKey::from_ssz_bytes(validator_pk) {
                Ok(v) => v,
                Err(_) => {
                    let log_clone = self.log.clone();
                    let f = sink
                        .fail(RpcStatus::new(
                            RpcStatusCode::InvalidArgument,
                            Some("Invalid public_key".to_string()),
                        ))
                        .map_err(move |_| warn!(log_clone, "failed to reply {:?}", req));
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
                    continue;
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
            let attestation_duties = match state
                .get_attestation_duties(val_index, RelativeEpoch::Current)
            {
                Ok(Some(v)) => v,
                Ok(_) => {
                    // validator is inactive, go to the next validator
                    warn!(
                        self.log,
                        "RPC requested an inactive validator key: {:?}", public_key
                    );
                    active_validator.set_none(false);
                    resp_validators.push(active_validator);
                    continue;
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
                    epoch.start_slot(T::EthSpec::slots_per_epoch()).as_u64() + slot as u64,
                );
            } else {
                // no blocks to propose this epoch
                duty.set_none(false)
            }

            duty.set_committee_index(attestation_duties.committee_index as u64);
            duty.set_attestation_slot(attestation_duties.slot.as_u64());
            duty.set_attestation_shard(attestation_duties.shard);
            duty.set_committee_len(attestation_duties.committee_len as u64);

            active_validator.set_duty(duty);
            resp_validators.push(active_validator);
        }

        let f = sink
            .success(resp)
            .map_err(move |e| println!("failed to reply {:?}: {:?}", req, e));
        ctx.spawn(f)
    }
}
