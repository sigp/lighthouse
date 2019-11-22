use crate::{
    duties_service::DutiesService, fork_service::ForkService, validator_store::ValidatorStore,
};
use environment::RuntimeContext;
use exit_future::Signal;
use futures::{Future, Stream};
use remote_beacon_node::{PublishStatus, RemoteBeaconNode, ValidatorDuty};
use slog::{error, info, trace};
use slot_clock::SlotClock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::timer::Interval;
use types::{ChainSpec, CommitteeIndex, EthSpec, Fork, Slot};

/// Delay this period of time after the slot starts. This allows the node to process the new slot.
const TIME_DELAY_FROM_SLOT: Duration = Duration::from_millis(100);

#[derive(Clone)]
pub struct AttestationServiceBuilder<T: Clone, E: EthSpec> {
    fork_service: Option<ForkService<T, E>>,
    duties_service: Option<DutiesService<T, E>>,
    validator_store: Option<ValidatorStore<E>>,
    slot_clock: Option<T>,
    beacon_node: Option<RemoteBeaconNode<E>>,
    context: Option<RuntimeContext<E>>,
}

// TODO: clean trait bounds.
impl<T: SlotClock + Clone + 'static, E: EthSpec> AttestationServiceBuilder<T, E> {
    pub fn new() -> Self {
        Self {
            fork_service: None,
            duties_service: None,
            validator_store: None,
            slot_clock: None,
            beacon_node: None,
            context: None,
        }
    }

    pub fn fork_service(mut self, service: ForkService<T, E>) -> Self {
        self.fork_service = Some(service);
        self
    }

    pub fn duties_service(mut self, service: DutiesService<T, E>) -> Self {
        self.duties_service = Some(service);
        self
    }

    pub fn validator_store(mut self, store: ValidatorStore<E>) -> Self {
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
                fork_service: self
                    .fork_service
                    .ok_or_else(|| "Cannot build AttestationService without fork_service")?,
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

pub struct Inner<T: Clone, E: EthSpec> {
    duties_service: DutiesService<T, E>,
    fork_service: ForkService<T, E>,
    validator_store: ValidatorStore<E>,
    slot_clock: T,
    beacon_node: RemoteBeaconNode<E>,
    context: RuntimeContext<E>,
}

#[derive(Clone)]
pub struct AttestationService<T: Clone, E: EthSpec> {
    inner: Arc<Inner<T, E>>,
}

// TODO: clean trait bounds.
impl<T: SlotClock + Clone + 'static, E: EthSpec> AttestationService<T, E> {
    pub fn start_update_service(&self, spec: &ChainSpec) -> Result<Signal, String> {
        let context = &self.inner.context;
        let log = context.log.clone();

        let duration_to_next_slot = self
            .inner
            .slot_clock
            .duration_to_next_slot()
            .ok_or_else(|| "Unable to determine duration to next slot".to_string())?;

        let interval = {
            let slot_duration = Duration::from_millis(spec.milliseconds_per_slot);
            Interval::new(
                Instant::now() + duration_to_next_slot * 3 / 2 + TIME_DELAY_FROM_SLOT,
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
                            error! {
                                log_1,
                                "Timer thread failed";
                                "error" => format!("{}", e)
                            }
                        })
                        .for_each(move |_| {
                            if let Err(e) = service.clone().spawn_attestation_tasks() {
                                error!(
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
                        })
                        // Prevent any errors from escaping and stopping the interval.
                        .then(|_| Ok(())),
                )
                .map(move |_| info!(log_3, "Shutdown complete")),
        );

        Ok(exit_signal)
    }

    fn spawn_attestation_tasks(&self) -> Result<(), String> {
        let inner = self.inner.clone();

        let slot = inner
            .slot_clock
            .now()
            .ok_or_else(|| "Failed to read slot clock".to_string())?;
        let fork = inner
            .fork_service
            .fork()
            .ok_or_else(|| "Failed to get Fork".to_string())?;

        let mut committee_indices: HashMap<CommitteeIndex, Vec<ValidatorDuty>> = HashMap::new();

        inner
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
                inner.context.executor.spawn(self.clone().do_attestation(
                    slot,
                    committee_index,
                    validator_duties,
                    fork.clone(),
                ));
            });

        Ok(())
    }

    fn do_attestation(
        self,
        slot: Slot,
        committee_index: CommitteeIndex,
        validator_duties: Vec<ValidatorDuty>,
        fork: Fork,
    ) -> impl Future<Item = (), Error = ()> {
        let inner_1 = self.inner.clone();
        let inner_2 = self.inner.clone();
        let log_1 = self.inner.context.log.clone();
        let log_2 = self.inner.context.log.clone();

        self.inner
            .beacon_node
            .http
            .validator()
            .produce_attestation(slot, committee_index)
            .map_err(|e| format!("Failed to produce attestation: {:?}", e))
            .and_then(move |attestation| {
                validator_duties
                    .iter()
                    .try_fold(attestation, |attestation, duty| {
                        let log = inner_1.context.log.clone();

                        if let Some((
                            duty_slot,
                            duty_committee_index,
                            validator_committee_position,
                        )) = attestation_duties(duty)
                        {
                            if duty_slot == slot && duty_committee_index == committee_index {
                                inner_1
                                    .validator_store
                                    .sign_attestation(
                                        &duty.validator_pubkey,
                                        validator_committee_position,
                                        attestation,
                                        &fork,
                                    )
                                    .ok_or_else(|| "Unable to sign attestation".to_string())
                            } else {
                                error!(log, "Inconsistent validator duties during signing");

                                Ok(attestation)
                            }
                        } else {
                            error!(log, "Missing validator duties when signing");

                            Ok(attestation)
                        }
                    })
            })
            .and_then(move |attestation| {
                inner_2
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
                PublishStatus::Invalid(msg) => error!(
                    log_1,
                    "Published attestation was invalid";
                    "message" => msg,
                    "committee_index" => attestation.data.index,
                    "slot" => attestation.data.slot.as_u64(),
                ),
                PublishStatus::Unknown => {
                    info!(log_1, "Unknown condition when publishing attestation")
                }
            })
            .map_err(move |e| {
                error!(
                    log_2,
                    "Error during attestation production";
                    "error" => e
                )
            })
    }
}

pub fn attestation_duties(duty: &ValidatorDuty) -> Option<(Slot, CommitteeIndex, usize)> {
    Some((
        duty.attestation_slot?,
        duty.attestation_committee_index?,
        duty.attestation_committee_position?,
    ))
}
