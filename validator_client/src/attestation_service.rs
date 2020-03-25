use crate::{
    duties_service::{DutiesService, DutyAndState},
    validator_store::ValidatorStore,
};
use environment::RuntimeContext;
use exit_future::Signal;
use futures::{future, Future, Stream};
use remote_beacon_node::{PublishStatus, RemoteBeaconNode};
use rest_types::ValidatorSubscription;
use slog::{crit, debug, info, trace};
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::timer::{Delay, Interval};
use types::{Attestation, ChainSpec, CommitteeIndex, EthSpec, Slot};

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

/// Helper to minimise `Arc` usage.
pub struct Inner<T, E: EthSpec> {
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
        let aggregate_production_instant = Instant::now()
            + duration_to_next_slot
                .checked_sub(slot_duration / 3)
                .unwrap_or_else(|| Duration::from_secs(0));

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

        let duties_by_committee_index: HashMap<CommitteeIndex, Vec<DutyAndState>> = service
            .duties_service
            .attesters(slot)
            .into_iter()
            .fold(HashMap::new(), |mut map, duty_and_state| {
                if let Some(committee_index) = duty_and_state.duty.attestation_committee_index {
                    let validator_duties = map.entry(committee_index).or_insert_with(|| vec![]);

                    validator_duties.push(duty_and_state);
                }

                map
            });

        // For each committee index for this slot:
        //
        // - Create and publish an `Attestation` for all required validators.
        // - Create and publish `SignedAggregateAndProof` for all aggregating validators.
        duties_by_committee_index
            .into_iter()
            .for_each(|(committee_index, validator_duties)| {
                // Spawn a separate task for each attestation.
                service
                    .context
                    .executor
                    .spawn(self.clone().publish_attestations_and_aggregates(
                        slot,
                        committee_index,
                        validator_duties,
                        aggregate_production_instant,
                    ));
            });

        Ok(())
    }

    /// Subscribes any required validators to the beacon node for a particular slot.
    ///
    /// This informs the beacon node that the validator has a duty on a particular
    /// slot allowing the beacon node to connect to the required subnet and determine
    /// if attestations need to be aggregated.
    fn send_subscriptions(&self, duties: Vec<DutyAndState>) -> impl Future<Item = (), Error = ()> {
        let mut validator_subscriptions = Vec::new();
        let mut successful_duties = Vec::new();

        let service_1 = self.clone();
        let duties_no = duties.len();

        let log_1 = self.context.log.clone();
        let log_2 = self.context.log.clone();

        // builds a list of subscriptions
        for duty in duties {
            if let Some((slot, attestation_committee_index, _, validator_index)) =
                duty.attestation_duties()
            {
                if let Some(slot_signature) = self
                    .validator_store
                    .sign_slot(duty.validator_pubkey(), slot)
                {
                    let is_aggregator_proof = if duty.is_aggregator() {
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
                        .subscribe_duty(&duty.duty, is_aggregator_proof);
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
    fn publish_attestations_and_aggregates(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
        validator_duties: Vec<DutyAndState>,
        aggregate_production_instant: Instant,
    ) -> Box<dyn Future<Item = (), Error = ()> + Send> {
        // There's not need to produce `Attestation` or `SignedAggregateAndProof` if we do not have
        // any validators for the given `slot` and `committee_index`.
        if validator_duties.is_empty() {
            return Box::new(future::ok(()));
        }

        let service_1 = self.clone();
        let log_1 = self.context.log.clone();
        let validator_duties_1 = Arc::new(validator_duties);
        let validator_duties_2 = validator_duties_1.clone();

        Box::new(
            // Step 1.
            //
            // Download, sign and publish an `Attestation` for each validator.
            self.produce_and_publish_attestations(slot, committee_index, validator_duties_1)
                .and_then::<_, Box<dyn Future<Item = _, Error = _> + Send>>(
                    move |attestation_opt| {
                        if let Some(attestation) = attestation_opt {
                            Box::new(
                                // Step 2. (Only if step 1 produced an attestation)
                                //
                                // First, wait until the `aggregation_production_instant` (2/3rds
                                // of the way though the slot). As verified in the
                                // `delay_triggers_when_in_the_past` test, this code will still run
                                // even if the instant has already elapsed.
                                //
                                // Then download, sign and publish a `SignedAggregateAndProof` for each
                                // validator that is elected to aggregate for this `slot` and
                                // `committee_index`.
                                Delay::new(aggregate_production_instant)
                                    .map_err(|e| {
                                        format!(
                                            "Unable to create aggregate production delay: {:?}",
                                            e
                                        )
                                    })
                                    .and_then(move |()| {
                                        service_1.produce_and_publish_aggregates(
                                            attestation,
                                            validator_duties_2,
                                        )
                                    }),
                            )
                        } else {
                            // If `produce_and_publish_attestations` did not download any
                            // attestations then there is no need to produce any
                            // `SignedAggregateAndProof`.
                            Box::new(future::ok(()))
                        }
                    },
                )
                .map_err(move |e| {
                    crit!(
                        log_1,
                        "Error during attestation routine";
                        "error" => format!("{:?}", e),
                        "committee_index" => committee_index,
                        "slot" => slot.as_u64(),
                    )
                }),
        )
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
    fn produce_and_publish_attestations(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
        validator_duties: Arc<Vec<DutyAndState>>,
    ) -> Box<dyn Future<Item = Option<Attestation<E>>, Error = String> + Send> {
        if validator_duties.is_empty() {
            return Box::new(future::ok(None));
        }

        let service = self.clone();

        Box::new(
            self.beacon_node
                .http
                .validator()
                .produce_attestation(slot, committee_index)
                .map_err(|e| format!("Failed to produce attestation: {:?}", e))
                .and_then::<_, Box<dyn Future<Item = _, Error = _> + Send>>(move |attestation| {
                    let log = service.context.log.clone();

                    // For each validator in `validator_duties`, clone the `attestation` and add
                    // their signature.
                    //
                    // If any validator is unable to sign, they are simply skipped.
                    let signed_attestations = validator_duties
                        .iter()
                        .filter_map(|duty| {
                            let log = service.context.log.clone();

                            // Ensure that all required fields are present in the validator duty.
                            let (duty_slot, duty_committee_index, validator_committee_position, _) =
                                if let Some(tuple) = duty.attestation_duties() {
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
                                    "validator" => format!("{:?}", duty.validator_pubkey()),
                                    "duty_slot" => duty_slot,
                                    "attestation_slot" => attestation.data.slot,
                                    "duty_index" => duty_committee_index,
                                    "attestation_index" => attestation.data.index,
                                );
                                return None;
                            }

                            let mut attestation = attestation.clone();

                            if service
                                .validator_store
                                .sign_attestation(
                                    duty.validator_pubkey(),
                                    validator_committee_position,
                                    &mut attestation,
                                )
                                .is_none()
                            {
                                crit!(
                                    log,
                                    "Attestation signing refused";
                                    "validator" => format!("{:?}", duty.validator_pubkey()),
                                    "slot" => attestation.data.slot,
                                    "index" => attestation.data.index,
                                );
                                None
                            } else {
                                Some(attestation)
                            }
                        })
                        .collect::<Vec<_>>();

                    // If there are any signed attestations, publish them to the BN. Otherwise,
                    // just return early.
                    if let Some(attestation) = signed_attestations.first().cloned() {
                        let num_attestations = signed_attestations.len();
                        let beacon_block_root = attestation.data.beacon_block_root;

                        Box::new(
                            service
                                .beacon_node
                                .http
                                .validator()
                                .publish_attestations(signed_attestations)
                                .map_err(|e| format!("Failed to publish attestation: {:?}", e))
                                .map(move |publish_status| match publish_status {
                                    PublishStatus::Valid => info!(
                                        log,
                                        "Successfully published attestations";
                                        "count" => num_attestations,
                                        "head_block" => format!("{:?}", beacon_block_root),
                                        "committee_index" => committee_index,
                                        "slot" => slot.as_u64(),
                                    ),
                                    PublishStatus::Invalid(msg) => crit!(
                                        log,
                                        "Published attestation was invalid";
                                        "message" => msg,
                                        "committee_index" => committee_index,
                                        "slot" => slot.as_u64(),
                                    ),
                                    PublishStatus::Unknown => {
                                        crit!(log, "Unknown condition when publishing attestation")
                                    }
                                })
                                .map(|()| Some(attestation)),
                        )
                    } else {
                        debug!(
                            log,
                            "No attestations to publish";
                            "committee_index" => committee_index,
                            "slot" => slot.as_u64(),
                        );
                        Box::new(future::ok(None))
                    }
                }),
        )
    }

    /// Performs the second step of the attesting process: downloading an aggregated `Attestation`,
    /// converting it into a `SignedAggregateAndProof` and returning it to the BN.
    ///
    /// https://github.com/ethereum/eth2.0-specs/blob/v0.11.0/specs/phase0/validator.md#broadcast-aggregate
    ///
    /// ## Detail
    ///
    /// The given `validator_duties` should already be filtered to only contain those that match
    /// `slot` and `committee_index`. Critical errors will be logged if this is not the case.
    ///
    /// Only one aggregated `Attestation` is downloaded from the BN. It is then cloned and signed
    /// by each validator and the list of individually-signed `SignedAggregateAndProof` objects is
    /// returned to the BN.
    fn produce_and_publish_aggregates(
        &self,
        attestation: Attestation<E>,
        validator_duties: Arc<Vec<DutyAndState>>,
    ) -> impl Future<Item = (), Error = String> {
        let service_1 = self.clone();
        let log_1 = self.context.log.clone();

        self.beacon_node
            .http
            .validator()
            .produce_aggregate_attestation(&attestation.data)
            .map_err(|e| format!("Failed to produce an aggregate attestation: {:?}", e))
            .and_then::<_, Box<dyn Future<Item = _, Error = _> + Send>>(
                move |aggregated_attestation| {
                    // For each validator, clone the `aggregated_attestation` and convert it into
                    // a `SignedAggregateAndProof`
                    let signed_aggregate_and_proofs = validator_duties
                        .iter()
                        .filter_map(|duty_and_state| {
                            // Do not produce a signed aggregator for validators that are not
                            // subscribed aggregators.
                            //
                            // Note: this function returns `false` if the validator is required to
                            // be an aggregator but has not yet subscribed.
                            if !duty_and_state.is_aggregator() {
                                return None;
                            }

                            let (duty_slot, duty_committee_index, _, validator_index) =
                                duty_and_state.attestation_duties().or_else(|| {
                                    crit!(log_1, "Missing duties when signing aggregate");
                                    None
                                })?;

                            let pubkey = &duty_and_state.duty.validator_pubkey;
                            let slot = attestation.data.slot;
                            let committee_index = attestation.data.index;

                            if duty_slot != slot || duty_committee_index != committee_index {
                                crit!(log_1, "Inconsistent validator duties during signing");
                                return None;
                            }

                            if let Some(signed_aggregate_and_proof) = service_1
                                .validator_store
                                .produce_signed_aggregate_and_proof(
                                    pubkey,
                                    validator_index,
                                    aggregated_attestation.clone(),
                                )
                            {
                                Some(signed_aggregate_and_proof)
                            } else {
                                crit!(log_1, "Failed to sign attestation");
                                None
                            }
                        })
                        .collect::<Vec<_>>();

                    // If there any signed aggregates and proofs were produced, publish them to the
                    // BN.
                    if let Some(first) = signed_aggregate_and_proofs.first().cloned() {
                        let attestation = first.message.aggregate;

                        Box::new(service_1
                        .beacon_node
                        .http
                        .validator()
                        .publish_aggregate_and_proof(signed_aggregate_and_proofs)
                        .map(|publish_status| (attestation, publish_status))
                        .map_err(|e| format!("Failed to publish aggregate and proofs: {:?}", e))
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
                        }))
                    } else {
                        debug!(
                            log_1,
                            "No signed aggregates to publish";
                            "committee_index" => attestation.data.index,
                            "slot" => attestation.data.slot.as_u64(),
                        );
                        Box::new(future::ok(()))
                    }
                },
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::RwLock;
    use tokio::runtime::Builder as RuntimeBuilder;

    /// This test is to ensure that a `tokio_timer::Delay` with an instant in the past will still
    /// trigger.
    #[test]
    fn delay_triggers_when_in_the_past() {
        let in_the_past = Instant::now() - Duration::from_secs(2);
        let state_1 = Arc::new(RwLock::new(in_the_past));
        let state_2 = state_1.clone();

        let future = Delay::new(in_the_past)
            .map_err(|_| panic!("Failed to create duration"))
            .map(move |()| *state_1.write() = Instant::now());

        let mut runtime = RuntimeBuilder::new()
            .core_threads(1)
            .build()
            .expect("failed to start runtime");

        runtime.block_on(future).expect("failed to complete future");

        assert!(
            *state_2.read() > in_the_past,
            "state should have been updated"
        );
    }
}
