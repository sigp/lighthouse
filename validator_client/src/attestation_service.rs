use crate::{
    duties_service::{DutiesService, DutyAndState},
    validator_store::ValidatorStore,
};
use environment::RuntimeContext;
use exit_future::Signal;
use futures::{Future, Stream};
use parking_lot::RwLock;
use remote_beacon_node::{PublishStatus, RemoteBeaconNode};
use rest_types::{ValidatorDuty, ValidatorSubscription};
use slog::{crit, info, trace};
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::timer::{Delay, Interval};
use types::{
    AggregateAndProof, AttestationData, ChainSpec, CommitteeIndex, Epoch, EthSpec, PublicKey, Slot,
};

/// The maximum number of epochs before some attestation at epoch `n` is no longer useful to be
/// published.
///
/// The beacon chain refuses attestations that are more than two epochs prior to the current slot.
/// As such, if we're halfway through epoch `n`, then we could submit an attestation for epochs
/// `(n, n-1, n-2)`.
///
/// Do not set to zero.
const ATTESTATION_PRODUCTION_DELAY_EPOCH: usize = 3;

/// Builds an `AttestationService`.
pub struct AttestationServiceBuilder<T, E: EthSpec> {
    duties_service: Option<DutiesService<T, E>>,
    validator_store: Option<ValidatorStore<T, E>>,
    slot_clock: Option<T>,
    beacon_node: Option<RemoteBeaconNode<E>>,
    context: Option<RuntimeContext<E>>,
}

impl<T: SlotClock + 'static, E: EthSpec> AttestationServiceBuilder<T, E> {
    pub fn new() -> Self {
        Self {
            duties_service: None,
            validator_store: None,
            slot_clock: None,
            beacon_node: None,
            context: None,
        }
    }

    pub fn duties_service(mut self, service: DutiesService<T, E>) -> Self {
        self.duties_service = Some(service);
        self
    }

    pub fn validator_store(mut self, store: ValidatorStore<T, E>) -> Self {
        self.validator_store = Some(store);
        self
    }

    pub fn slot_clock(mut self, slot_clock: T) -> Self {
        self.slot_clock = Some(slot_clock);
        self
    }

    pub fn beacon_node(mut self, beacon_node: RemoteBeaconNode<E>) -> Self {
        self.beacon_node = Some(beacon_node);
        self
    }

    pub fn runtime_context(mut self, context: RuntimeContext<E>) -> Self {
        self.context = Some(context);
        self
    }

    pub fn build(self) -> Result<AttestationService<T, E>, String> {
        Ok(AttestationService {
            inner: Arc::new(Inner {
                stored_attestation_data: <_>::default(),
                duties_service: self
                    .duties_service
                    .ok_or_else(|| "Cannot build AttestationService without duties_service")?,
                validator_store: self
                    .validator_store
                    .ok_or_else(|| "Cannot build AttestationService without validator_store")?,
                slot_clock: self
                    .slot_clock
                    .ok_or_else(|| "Cannot build AttestationService without slot_clock")?,
                beacon_node: self
                    .beacon_node
                    .ok_or_else(|| "Cannot build AttestationService without beacon_node")?,
                context: self
                    .context
                    .ok_or_else(|| "Cannot build AttestationService without runtime_context")?,
            }),
        })
    }
}

#[derive(Default)]
struct StoredAttestationData(
    RwLock<HashMap<PublicKey, [Option<AttestationData>; ATTESTATION_PRODUCTION_DELAY_EPOCH]>>,
);

impl StoredAttestationData {
    pub fn insert<E: EthSpec>(
        &self,
        validator_pubkey: &PublicKey,
        data: AttestationData,
    ) -> Result<(), ()> {
        let epoch = |data: &AttestationData| -> Epoch { data.slot.epoch(E::slots_per_epoch()) };
        let mut map = self.0.write();

        if let Some(values) = map.get_mut(validator_pubkey) {
            let conflict_exists = values[..].iter().any(|stored_data_opt| {
                stored_data_opt
                    .as_ref()
                    .map_or(false, |stored_data| epoch(stored_data) == epoch(&data))
            });

            if conflict_exists {
                return Err(());
            }

            let delay = Epoch::from(ATTESTATION_PRODUCTION_DELAY_EPOCH - 1);

            let position = values[..]
                .iter()
                .position(|stored_data_opt| {
                    stored_data_opt.as_ref().map_or(true, |stored_data| {
                        epoch(stored_data) + delay < epoch(&data)
                    })
                })
                .ok_or_else(|| ())?;

            values[position] = Some(data);
        } else {
            map.insert(validator_pubkey.clone(), [Some(data), None, None]);
        }

        Ok(())
    }
}

/// Helper to minimise `Arc` usage.
pub struct Inner<T, E: EthSpec> {
    stored_attestation_data: StoredAttestationData,
    duties_service: DutiesService<T, E>,
    validator_store: ValidatorStore<T, E>,
    slot_clock: T,
    beacon_node: RemoteBeaconNode<E>,
    context: RuntimeContext<E>,
}

/// Attempts to produce attestations for all known validators 1/3rd of the way through each slot.
///
/// If any validators are on the same committee, a single attestation will be downloaded and
/// returned to the beacon node. This attestation will have a signature from each of the
/// validators.
pub struct AttestationService<T, E: EthSpec> {
    inner: Arc<Inner<T, E>>,
}

impl<T, E: EthSpec> Clone for AttestationService<T, E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T, E: EthSpec> Deref for AttestationService<T, E> {
    type Target = Inner<T, E>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl<T: SlotClock + 'static, E: EthSpec> AttestationService<T, E> {
    /// Starts the service which periodically produces attestations.
    pub fn start_update_service(&self, spec: &ChainSpec) -> Result<Signal, String> {
        let context = &self.context;
        let log = context.log.clone();

        let slot_duration = Duration::from_millis(spec.milliseconds_per_slot);
        let duration_to_next_slot = self
            .slot_clock
            .duration_to_next_slot()
            .ok_or_else(|| "Unable to determine duration to next slot".to_string())?;

        let interval = {
            Interval::new(
                Instant::now() + duration_to_next_slot + slot_duration / 3,
                slot_duration,
            )
        };

        let (exit_signal, exit_fut) = exit_future::signal();
        let service = self.clone();
        let log_1 = log.clone();
        let log_2 = log.clone();
        let log_3 = log.clone();

        context.executor.spawn(
            exit_fut
                .until(
                    interval
                        .map_err(move |e| {
                            crit! {
                                log_1,
                                "Timer thread failed";
                                "error" => format!("{}", e)
                            }
                        })
                        .for_each(move |_| {
                            if let Err(e) = service.spawn_attestation_tasks(slot_duration) {
                                crit!(
                                    log_2,
                                    "Failed to spawn attestation tasks";
                                    "error" => e
                                )
                            } else {
                                trace!(
                                    log_2,
                                    "Spawned attestation tasks";
                                )
                            }

                            Ok(())
                        }),
                )
                .map(move |_| info!(log_3, "Shutdown complete")),
        );

        Ok(exit_signal)
    }

    /// For each each required attestation, spawn a new task that downloads, signs and uploads the
    /// attestation to the beacon node.
    fn spawn_attestation_tasks(&self, slot_duration: Duration) -> Result<(), String> {
        let service = self.clone();

        let slot = service
            .slot_clock
            .now()
            .ok_or_else(|| "Failed to read slot clock".to_string())?;
        let duration_to_next_slot = service
            .slot_clock
            .duration_to_next_slot()
            .ok_or_else(|| "Unable to determine duration to next slot".to_string())?;

        // If a validator needs to publish an aggregate attestation, they must do so at 2/3
        // through the slot. This delay triggers at this time
        let aggregator_delay_instant = {
            if duration_to_next_slot <= slot_duration / 3 {
                Instant::now()
            } else {
                Instant::now() + duration_to_next_slot - (slot_duration / 3)
            }
        };

        let epoch = slot.epoch(E::slots_per_epoch());
        // Check if any attestation subscriptions are required. If there a new attestation duties for
        // this epoch or the next, send them to the beacon node
        let mut duties_to_subscribe = service.duties_service.unsubscribed_epoch_duties(&epoch);
        duties_to_subscribe.append(
            &mut service
                .duties_service
                .unsubscribed_epoch_duties(&(epoch + 1)),
        );

        // spawn a task to subscribe all the duties
        service
            .context
            .executor
            .spawn(self.clone().send_subscriptions(duties_to_subscribe));

        // Builds a map of committee index and spawn individual tasks to process raw attestations
        // and aggregated attestations
        let mut committee_indices: HashMap<CommitteeIndex, Vec<ValidatorDuty>> = HashMap::new();
        let mut aggregator_committee_indices: HashMap<CommitteeIndex, Vec<DutyAndState>> =
            HashMap::new();

        service
            .duties_service
            .attesters(slot)
            .into_iter()
            .for_each(|duty_and_state| {
                if let Some(committee_index) = duty_and_state.duty.attestation_committee_index {
                    let validator_duties = committee_indices
                        .entry(committee_index)
                        .or_insert_with(|| vec![]);
                    validator_duties.push(duty_and_state.duty.clone());

                    // If this duty entails the validator aggregating attestations, perform
                    // aggregation tasks
                    if duty_and_state.is_aggregator() {
                        let validator_duties = aggregator_committee_indices
                            .entry(committee_index)
                            .or_insert_with(|| vec![]);
                        validator_duties.push(duty_and_state);
                    }
                }
            });

        // spawns tasks for all required raw attestations production
        committee_indices
            .into_iter()
            .for_each(|(committee_index, validator_duties)| {
                // Spawn a separate task for each attestation.
                service
                    .context
                    .executor
                    .spawn(self.clone().produce_sign_and_publish_attestations(
                        slot,
                        committee_index,
                        validator_duties,
                    ));
            });

        // spawns tasks for all aggregate attestation production
        aggregator_committee_indices
            .into_iter()
            .for_each(|(committee_index, validator_duties)| {
                // Spawn a separate task for each aggregate attestation.
                service
                    .context
                    .executor
                    .spawn(self.clone().do_aggregate_attestation(
                        slot,
                        committee_index,
                        validator_duties,
                        Delay::new(aggregator_delay_instant.clone()),
                    ));
            });
        Ok(())
    }

    /// Subscribes any required validators to the beacon node for a particular slot.
    ///
    /// This informs the beacon node that the validator has a duty on a particular
    /// slot allowing the beacon node to connect to the required subnet and determine
    /// if attestations need to be aggregated.
    fn send_subscriptions(&self, duties: Vec<ValidatorDuty>) -> impl Future<Item = (), Error = ()> {
        let mut validator_subscriptions = Vec::new();
        let mut successful_duties = Vec::new();

        let service_1 = self.clone();
        let duties_no = duties.len();

        let log_1 = self.context.log.clone();
        let log_2 = self.context.log.clone();

        // builds a list of subscriptions
        for duty in duties {
            if let Some((slot, attestation_committee_index, _, validator_index)) =
                attestation_duties(&duty)
            {
                if let Some(slot_signature) =
                    self.validator_store.sign_slot(&duty.validator_pubkey, slot)
                {
                    let is_aggregator_proof = if duty.is_aggregator(&slot_signature) {
                        Some(slot_signature.clone())
                    } else {
                        None
                    };

                    let subscription = ValidatorSubscription::new(
                        validator_index,
                        attestation_committee_index,
                        slot,
                        slot_signature,
                    );
                    validator_subscriptions.push(subscription);

                    // add successful duties to the list, along with whether they are aggregation
                    // duties or not
                    successful_duties.push((duty, is_aggregator_proof));
                }
            } else {
                crit!(log_2, "Validator duty doesn't have required fields");
            }
        }

        let failed_duties = duties_no - successful_duties.len();

        self.beacon_node
            .http
            .validator()
            .subscribe(validator_subscriptions)
            .map_err(|e| format!("Failed to subscribe validators: {:?}", e))
            .map(move |publish_status| match publish_status {
                PublishStatus::Valid => info!(
                    log_1,
                    "Successfully subscribed validators";
                    "validators" => duties_no,
                    "failed_validators" => failed_duties,
                ),
                PublishStatus::Invalid(msg) => crit!(
                    log_1,
                    "Validator Subscription was invalid";
                    "message" => msg,
                ),
                PublishStatus::Unknown => {
                    crit!(log_1, "Unknown condition when publishing attestation")
                }
            })
            .and_then(move |_| {
                for (duty, is_aggregator_proof) in successful_duties {
                    service_1
                        .duties_service
                        .subscribe_duty(&duty, is_aggregator_proof);
                }
                Ok(())
            })
            .map_err(move |e| {
                crit!(
                    log_2,
                    "Error during attestation production";
                    "error" => e
                )
            })
    }

    /// Performs the first step of the attesting process: downloading `Attestation` objects,
    /// signing them and returning them to the validator.
    ///
    /// https://github.com/ethereum/eth2.0-specs/blob/v0.11.0/specs/phase0/validator.md#attesting
    ///
    /// ## Detail
    ///
    /// The given `validator_duties` should already be filtered to only contain those that match
    /// `slot` and `committee_index`. Critical errors will be logged if this is not the case.
    ///
    /// Only one `Attestation` is downloaded from the BN. It is then cloned and signed by each
    /// validator and the list of individually-signed `Attestation` objects is returned to the BN.
    fn produce_sign_and_publish_attestations(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
        validator_duties: Vec<ValidatorDuty>,
    ) -> impl Future<Item = (), Error = ()> {
        let service_1 = self.clone();
        let service_2 = self.clone();
        let log_1 = self.context.log.clone();
        let log_2 = self.context.log.clone();

        self.beacon_node
            .http
            .validator()
            .produce_attestation(slot, committee_index)
            .map_err(|e| format!("Failed to produce attestation: {:?}", e))
            .map(move |attestation| {
                validator_duties
                    .iter()
                    .filter_map(|duty| {
                        let log = service_1.context.log.clone();

                        // Ensure that all required fields are present in the validator duty.
                        let (duty_slot, duty_committee_index, validator_committee_position, _) =
                            if let Some(tuple) = attestation_duties(duty) {
                                tuple
                            } else {
                                crit!(
                                    log,
                                    "Missing validator duties when signing";
                                    "duties" => format!("{:?}", duty)
                                );
                                return None;
                            };

                        // Ensure that the attestation matches the duties.
                        if duty_slot != attestation.data.slot
                            || duty_committee_index != attestation.data.index
                        {
                            crit!(
                                log,
                                "Inconsistent validator duties during signing";
                                "validator" => format!("{:?}", &duty.validator_pubkey),
                                "duty_slot" => duty_slot,
                                "attestation_slot" => attestation.data.slot,
                                "duty_index" => duty_committee_index,
                                "attestation_index" => attestation.data.index,
                            );
                            return None;
                        }

                        // Attempt to store the `attestation.data` so it can later be
                        // recalled when it is time for the validator to publish
                        if let Err(()) = service_1
                            .stored_attestation_data
                            .insert::<E>(&duty.validator_pubkey, attestation.data.clone())
                        {
                            crit!(
                                log,
                                "Conflicting attestation detected, aborting";
                                "validator" => format!("{:?}", &duty.validator_pubkey),
                                "slot" => attestation.data.slot,
                                "index" => attestation.data.index,
                            );
                            return None;
                        }

                        let mut attestation = attestation.clone();

                        if service_1
                            .validator_store
                            .sign_attestation(
                                &duty.validator_pubkey,
                                validator_committee_position,
                                &mut attestation,
                            )
                            .is_none()
                        {
                            crit!(
                                log,
                                "Attestation signing refused";
                                "validator" => format!("{:?}", &duty.validator_pubkey),
                                "slot" => attestation.data.slot,
                                "index" => attestation.data.index,
                            );
                            None
                        } else {
                            Some(attestation)
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .and_then(move |attestations| {
                let num_attestations = attestations.len();
                let beacon_block_root = attestations.first().map(|a| a.data.beacon_block_root);
                service_2
                    .beacon_node
                    .http
                    .validator()
                    .publish_attestations(attestations)
                    .map(move |publish_status| {
                        (num_attestations, beacon_block_root, publish_status)
                    })
                    .map_err(|e| format!("Failed to publish attestations: {:?}", e))
            })
            .map(
                move |(num_attestations, beacon_block_root, publish_status)| match publish_status {
                    PublishStatus::Valid => info!(
                        log_1,
                        "Successfully published attestations";
                        "count" => num_attestations,
                        "head_block" => format!("{:?}", beacon_block_root),
                        "committee_index" => committee_index,
                        "slot" => slot.as_u64(),
                    ),
                    PublishStatus::Invalid(msg) => crit!(
                        log_1,
                        "Published attestation was invalid";
                        "message" => msg,
                        "committee_index" => committee_index,
                        "slot" => slot.as_u64(),
                    ),
                    PublishStatus::Unknown => {
                        crit!(log_1, "Unknown condition when publishing attestation")
                    }
                },
            )
            .map_err(move |e| {
                crit!(
                    log_2,
                    "Error during attestation production";
                    "error" => e
                )
            })
    }

    /// For a given `committee_index`, download the aggregate attestation, have it signed by all validators
    /// in `validator_duties` then upload it.
    fn do_aggregate_attestation(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
        validator_duties: Vec<DutyAndState>,
        aggregator_delay: Delay,
    ) -> impl Future<Item = (), Error = ()> {
        let service_1 = self.clone();
        let service_2 = self.clone();
        let log_1 = self.context.log.clone();
        let log_2 = self.context.log.clone();

        self.beacon_node
            .http
            .validator()
            .produce_aggregate_attestation(slot, committee_index)
            .map_err(|e| format!("Failed to produce an aggregate attestation: {:?}", e))
            .map(move |attestation| {
                validator_duties.iter().fold(
                    (Vec::new(), attestation),
                    |(mut aggregate_and_proof_list, attestation), duty_and_state| {
                        let log = service_1.context.log.clone();

                        match (
                            duty_and_state.selection_proof(),
                            attestation_duties(&duty_and_state.duty),
                        ) {
                            (
                                Some(selection_proof),
                                Some((duty_slot, duty_committee_index, _, aggregator_index)),
                            ) => {
                                let pubkey = &duty_and_state.duty.validator_pubkey;

                                if duty_slot != slot || duty_committee_index != committee_index {
                                    crit!(log, "Inconsistent validator duties during signing");
                                    return (aggregate_and_proof_list, attestation);
                                }

                                let raw_attestation = attestation.clone();
                                // build the `AggregateAndProof` struct for each validator
                                let aggregate_and_proof = AggregateAndProof {
                                    aggregator_index,
                                    aggregate: raw_attestation,
                                    selection_proof,
                                };

                                if let Some(signed_aggregate_and_proof) = service_1
                                    .validator_store
                                    .sign_aggregate_and_proof(pubkey, aggregate_and_proof)
                                {
                                    aggregate_and_proof_list.push(signed_aggregate_and_proof);
                                } else {
                                    crit!(log, "Failed to sign attestation");
                                }
                            }
                            _ => crit!(
                                log,
                                "Missing validator duties or not aggregate duty when signing"
                            ),
                        }

                        (aggregate_and_proof_list, attestation)
                    },
                )
            })
            .and_then(move |(aggregate_and_proof_list, attestation)| {
                aggregator_delay
                    .map(move |_| (aggregate_and_proof_list, attestation))
                    .map_err(move |e| format!("Error during aggregator delay: {:?}", e))
            })
            .and_then(move |(aggregate_and_proof_list, attestation)| {
                service_2
                    .beacon_node
                    .http
                    .validator()
                    .publish_aggregate_and_proof(aggregate_and_proof_list)
                    .map(|publish_status| (attestation, publish_status))
                    .map_err(|e| format!("Failed to publish aggregate and proofs: {:?}", e))
            })
            .map(move |(attestation, publish_status)| match publish_status {
                PublishStatus::Valid => info!(
                    log_1,
                    "Successfully published aggregate attestations";
                    "signatures" => attestation.aggregation_bits.num_set_bits(),
                    "head_block" => format!("{}", attestation.data.beacon_block_root),
                    "committee_index" => attestation.data.index,
                    "slot" => attestation.data.slot.as_u64(),
                ),
                PublishStatus::Invalid(msg) => crit!(
                    log_1,
                    "Published attestation was invalid";
                    "message" => msg,
                    "committee_index" => attestation.data.index,
                    "slot" => attestation.data.slot.as_u64(),
                ),
                PublishStatus::Unknown => {
                    crit!(log_1, "Unknown condition when publishing attestation")
                }
            })
            .map_err(move |e| {
                crit!(
                    log_2,
                    "Error during attestation production";
                    "error" => e
                )
            })
    }
}

fn attestation_duties(duty: &ValidatorDuty) -> Option<(Slot, CommitteeIndex, usize, u64)> {
    Some((
        duty.attestation_slot?,
        duty.attestation_committee_index?,
        duty.attestation_committee_position?,
        duty.validator_index?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_delay_constant() {
        assert!(
            ATTESTATION_PRODUCTION_DELAY_EPOCH > 1,
            "an underflow will occur if ATTESTATION_PRODUCTION_DELAY_EPOCH is zero"
        );
    }
}
