use crate::{duties_service::DutiesService, validator_store::ValidatorStore};
use environment::RuntimeContext;
use exit_future::Signal;
use futures::{stream, Future, IntoFuture, Stream};
use remote_beacon_node::{PublishStatus, RemoteBeaconNode};
use slog::{crit, error, info, trace};
use slot_clock::SlotClock;
use std::ops::Deref;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::timer::Interval;
use types::{ChainSpec, EthSpec};

/// Delay this period of time after the slot starts. This allows the node to process the new slot.
const TIME_DELAY_FROM_SLOT: Duration = Duration::from_millis(100);

/// Builds a `BlockService`.
pub struct BlockServiceBuilder<T, E: EthSpec> {
    duties_service: Option<DutiesService<T, E>>,
    validator_store: Option<ValidatorStore<T, E>>,
    slot_clock: Option<Arc<T>>,
    beacon_node: Option<RemoteBeaconNode<E>>,
    context: Option<RuntimeContext<E>>,
}

impl<T: SlotClock + 'static, E: EthSpec> BlockServiceBuilder<T, E> {
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

    pub fn build(self) -> Result<BlockService<T, E>, String> {
        Ok(BlockService {
            inner: Arc::new(Inner {
                duties_service: self
                    .duties_service
                    .ok_or_else(|| "Cannot build BlockService without duties_service")?,
                validator_store: self
                    .validator_store
                    .ok_or_else(|| "Cannot build BlockService without validator_store")?,
                slot_clock: self
                    .slot_clock
                    .ok_or_else(|| "Cannot build BlockService without slot_clock")?,
                beacon_node: self
                    .beacon_node
                    .ok_or_else(|| "Cannot build BlockService without beacon_node")?,
                context: self
                    .context
                    .ok_or_else(|| "Cannot build BlockService without runtime_context")?,
            }),
        })
    }
}

/// Helper to minimise `Arc` usage.
pub struct Inner<T, E: EthSpec> {
    duties_service: DutiesService<T, E>,
    validator_store: ValidatorStore<T, E>,
    slot_clock: Arc<T>,
    beacon_node: RemoteBeaconNode<E>,
    context: RuntimeContext<E>,
}

/// Attempts to produce attestations for any block producer(s) at the start of the epoch.
pub struct BlockService<T, E: EthSpec> {
    inner: Arc<Inner<T, E>>,
}

impl<T, E: EthSpec> Clone for BlockService<T, E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T, E: EthSpec> Deref for BlockService<T, E> {
    type Target = Inner<T, E>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl<T: SlotClock + 'static, E: EthSpec> BlockService<T, E> {
    /// Starts the service that periodically attempts to produce blocks.
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

        let (exit_signal, exit_fut) = exit_future::signal();
        let service = self.clone();
        let log_1 = log.clone();
        let log_2 = log.clone();

        self.context.executor.spawn(
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
                        .for_each(move |_| service.clone().do_update())
                        // Prevent any errors from escaping and stopping the interval.
                        .then(|_| Ok(())),
                )
                .map(move |_| info!(log_2, "Shutdown complete")),
        );

        Ok(exit_signal)
    }

    /// Attempt to produce a block for any block producers in the `ValidatorStore`.
    fn do_update(self) -> impl Future<Item = (), Error = ()> {
        let service = self.clone();
        let log_1 = self.context.log.clone();
        let log_2 = self.context.log.clone();

        self.slot_clock
            .now()
            .ok_or_else(move || {
                crit!(log_1, "Duties manager failed to read slot clock");
            })
            .into_future()
            .and_then(move |slot| {
                let iter = service.duties_service.block_producers(slot).into_iter();

                if iter.len() == 0 {
                    trace!(
                        log_2,
                        "No local block proposers for this slot";
                        "slot" => slot.as_u64()
                    )
                } else if iter.len() > 1 {
                    error!(
                        log_2,
                        "Multiple block proposers for this slot";
                        "action" => "producing blocks for all proposers",
                        "num_proposers" => iter.len(),
                        "slot" => slot.as_u64(),
                    )
                }

                stream::unfold(iter, move |mut block_producers| {
                    let log_1 = service.context.log.clone();
                    let log_2 = service.context.log.clone();
                    let service_1 = service.clone();
                    let service_2 = service.clone();
                    let service_3 = service.clone();

                    block_producers.next().map(move |validator_pubkey| {
                        service_1
                            .validator_store
                            .randao_reveal(&validator_pubkey, slot.epoch(E::slots_per_epoch()))
                            .ok_or_else(|| "Unable to produce randao reveal".to_string())
                            .into_future()
                            .and_then(move |randao_reveal| {
                                service_1
                                    .beacon_node
                                    .http
                                    .validator()
                                    .produce_block(slot, randao_reveal)
                                    .map_err(|e| {
                                        format!(
                                            "Error from beacon node when producing block: {:?}",
                                            e
                                        )
                                    })
                            })
                            .and_then(move |block| {
                                service_2
                                    .validator_store
                                    .sign_block(&validator_pubkey, block)
                                    .ok_or_else(|| "Unable to sign block".to_string())
                            })
                            .and_then(move |block| {
                                service_3
                                    .beacon_node
                                    .http
                                    .validator()
                                    .publish_block(block.clone())
                                    .map(|publish_status| (block, publish_status))
                                    .map_err(|e| {
                                        format!(
                                            "Error from beacon node when publishing block: {:?}",
                                            e
                                        )
                                    })
                            })
                            .map(move |(block, publish_status)| match publish_status {
                                PublishStatus::Valid => info!(
                                    log_1,
                                    "Successfully published block";
                                    "deposits" => block.body.deposits.len(),
                                    "attestations" => block.body.attestations.len(),
                                    "slot" => block.slot.as_u64(),
                                ),
                                PublishStatus::Invalid(msg) => crit!(
                                    log_1,
                                    "Published block was invalid";
                                    "message" => msg,
                                    "slot" => block.slot.as_u64(),
                                ),
                                PublishStatus::Unknown => {
                                    crit!(log_1, "Unknown condition when publishing block")
                                }
                            })
                            .map_err(move |e| {
                                crit!(
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
