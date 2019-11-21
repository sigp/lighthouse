use crate::{
    duties_service::DutiesService, fork_service::ForkService, validator_store::ValidatorStore,
};
use environment::RuntimeContext;
use exit_future::Signal;
use futures::{stream, Future, IntoFuture, Stream};
use remote_beacon_node::{PublishStatus, RemoteBeaconNode};
use slog::{error, info, trace, warn};
use slot_clock::SlotClock;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::timer::Interval;
use types::{ChainSpec, EthSpec};

/// Delay this period of time after the slot starts. This allows the node to process the new slot.
const TIME_DELAY_FROM_SLOT: Duration = Duration::from_millis(100);

#[derive(Clone)]
pub struct AttestationServiceBuilder<T: Clone, E: EthSpec> {
    fork_service: Option<ForkService<T, E>>,
    duties_service: Option<DutiesService<T, E>>,
    validator_store: Option<ValidatorStore<E>>,
    slot_clock: Option<Arc<T>>,
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
        self.slot_clock = Some(Arc::new(slot_clock));
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
        })
    }
}

#[derive(Clone)]
pub struct AttestationService<T: Clone, E: EthSpec> {
    duties_service: DutiesService<T, E>,
    fork_service: ForkService<T, E>,
    validator_store: ValidatorStore<E>,
    slot_clock: Arc<T>,
    beacon_node: RemoteBeaconNode<E>,
    context: RuntimeContext<E>,
}

// TODO: clean trait bounds.
impl<T: SlotClock + Clone + 'static, E: EthSpec> AttestationService<T, E> {
    pub fn start_update_service(&self, spec: &ChainSpec) -> Result<Signal, String> {
        let log = self.context.log.clone();

        let duration_to_next_slot = self
            .slot_clock
            .duration_to_next_slot()
            .ok_or_else(|| "Unable to determine duration to next slot".to_string())?;

        let interval = {
            let slot_duration = Duration::from_millis(spec.milliseconds_per_slot);
            Interval::new(
                Instant::now() + duration_to_next_slot + TIME_DELAY_FROM_SLOT,
                slot_duration,
            )
        };

        info!(
            log,
            "Waiting for next slot";
            "seconds_to_wait" => duration_to_next_slot.as_secs()
        );

        let (exit_signal, exit_fut) = exit_future::signal();
        let service = self.clone();

        self.context.executor.spawn(
            interval
                .map_err(move |e| {
                    error! {
                        log,
                        "Timer thread failed";
                        "error" => format!("{}", e)
                    }
                })
                .and_then(move |_| if exit_fut.is_live() { Ok(()) } else { Err(()) })
                .for_each(move |_| service.clone().do_update()),
        );

        Ok(exit_signal)
    }

    fn do_update(self) -> impl Future<Item = (), Error = ()> {
        let service = self.clone();
        let log = self.context.log.clone();

        self.slot_clock
            .now()
            .ok_or_else(move || {
                error!(log, "Duties manager failed to read slot clock");
            })
            .into_future()
            .and_then(move |slot| {
                let iter = service.duties_service.block_producers(slot).into_iter();

                stream::unfold(iter, move |mut block_producers| {
                    let log_1 = service.context.log.clone();
                    let log_2 = service.context.log.clone();
                    let service_1 = service.clone();
                    let service_2 = service.clone();
                    let service_3 = service.clone();

                    block_producers.next().map(move |validator_pubkey| {
                        service_2
                            .fork_service
                            .fork()
                            .ok_or_else(|| "Fork is unknown, unable to sign".to_string())
                            .and_then(|fork| {
                                service_1
                                    .validator_store
                                    .randao_reveal(
                                        &validator_pubkey,
                                        slot.epoch(E::slots_per_epoch()),
                                        &fork,
                                    )
                                    .map(|randao_reveal| (fork, randao_reveal))
                                    .ok_or_else(|| "Unable to produce randao reveal".to_string())
                            })
                            .into_future()
                            .and_then(move |(fork, randao_reveal)| {
                                service_1
                                    .beacon_node
                                    .http
                                    .validator()
                                    .produce_block(slot, randao_reveal)
                                    .map(|block| (fork, block))
                                    .map_err(|e| {
                                        format!(
                                            "Error from beacon node when producing block: {:?}",
                                            e
                                        )
                                    })
                            })
                            .and_then(move |(fork, block)| {
                                service_2
                                    .validator_store
                                    .sign_block(&validator_pubkey, block, &fork)
                                    .ok_or_else(|| "Unable to sign block".to_string())
                            })
                            .and_then(move |block| {
                                service_3
                                    .beacon_node
                                    .http
                                    .validator()
                                    .publish_block(block)
                                    .map_err(|e| {
                                        format!(
                                            "Error from beacon node when publishing block: {:?}",
                                            e
                                        )
                                    })
                            })
                            .map(move |publish_outcome| match publish_outcome {
                                PublishStatus::Valid => {
                                    info!(log_1, "Successfully published block")
                                }
                                PublishStatus::Invalid(msg) => error!(
                                    log_1,
                                    "Published block was invalid";
                                    "message" => msg
                                ),
                                PublishStatus::Unknown => {
                                    info!(log_1, "Unknown condition when publishing block")
                                }
                            })
                            .map_err(move |e| {
                                error!(
                                    log_2,
                                    "Error whilst producing block";
                                    "message" => e
                                )
                            })
                            .then(|_| Ok(((), block_producers)))
                    })
                })
                .collect()
                .map(|_| ())
            })
    }
}
