use crate::{
    duties_service::{DutiesService, ValidatorDuty},
    validator_store::ValidatorStore,
};
use environment::RuntimeContext;
use exit_future::Signal;
use futures::{Future, Stream};
use remote_beacon_node::{PublishStatus, RemoteBeaconNode};
use slog::{crit, info, trace};
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::timer::Interval;
use types::{ChainSpec, CommitteeIndex, EthSpec, Slot};

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

        let duration_to_next_slot = self
            .slot_clock
            .duration_to_next_slot()
            .ok_or_else(|| "Unable to determine duration to next slot".to_string())?;

        let interval = {
            let slot_duration = Duration::from_millis(spec.milliseconds_per_slot);
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
                            if let Err(e) = service.spawn_attestation_tasks() {
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
    fn spawn_attestation_tasks(&self) -> Result<(), String> {
        let service = self.clone();

        let slot = service
            .slot_clock
            .now()
            .ok_or_else(|| "Failed to read slot clock".to_string())?;

        let mut committee_indices: HashMap<CommitteeIndex, Vec<ValidatorDuty>> = HashMap::new();

        service
            .duties_service
            .attesters(slot)
            .into_iter()
            .for_each(|duty| {
                if let Some(committee_index) = duty.attestation_committee_index {
                    let validator_duties =
                        committee_indices.entry(committee_index).or_insert(vec![]);

                    validator_duties.push(duty);
                }
            });

        committee_indices
            .into_iter()
            .for_each(|(committee_index, validator_duties)| {
                // Spawn a separate task for each attestation.
                service.context.executor.spawn(self.clone().do_attestation(
                    slot,
                    committee_index,
                    validator_duties,
                ));
            });

        Ok(())
    }

    /// For a given `committee_index`, download the attestation, have it signed by all validators
    /// in `validator_duties` then upload it.
    fn do_attestation(
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
                    .fold(attestation, |mut attestation, duty| {
                        let log = service_1.context.log.clone();

                        if let Some((
                            duty_slot,
                            duty_committee_index,
                            validator_committee_position,
                        )) = attestation_duties(duty)
                        {
                            if duty_slot == slot && duty_committee_index == committee_index {
                                if service_1
                                    .validator_store
                                    .sign_attestation(
                                        &duty.validator_pubkey,
                                        validator_committee_position,
                                        &mut attestation,
                                    )
                                    .is_none()
                                {
                                    crit!(log, "Failed to sign attestation");
                                }
                            } else {
                                crit!(log, "Inconsistent validator duties during signing");
                            }
                        } else {
                            crit!(log, "Missing validator duties when signing");
                        }

                        attestation
                    })
            })
            .and_then(move |attestation| {
                service_2
                    .beacon_node
                    .http
                    .validator()
                    .publish_attestation(attestation.clone())
                    .map(|publish_status| (attestation, publish_status))
                    .map_err(|e| format!("Failed to publish attestation: {:?}", e))
            })
            .map(move |(attestation, publish_status)| match publish_status {
                PublishStatus::Valid => info!(
                    log_1,
                    "Successfully published attestation";
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

fn attestation_duties(duty: &ValidatorDuty) -> Option<(Slot, CommitteeIndex, usize)> {
    Some((
        duty.attestation_slot?,
        duty.attestation_committee_index?,
        duty.attestation_committee_position?,
    ))
}
