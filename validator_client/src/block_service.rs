use crate::{duties_service::DutiesService, validator_store::ValidatorStore};
use environment::RuntimeContext;
use exit_future::Signal;
use futures::{FutureExt, StreamExt, TryFutureExt};
use remote_beacon_node::{PublishStatus, RemoteBeaconNode};
use slog::{crit, error, info, trace};
use slot_clock::SlotClock;
use std::ops::Deref;
use std::sync::Arc;
use tokio::time::{interval_at, Duration, Instant};
use types::{ChainSpec, EthSpec, PublicKey, Slot};

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
    pub fn start_update_service(self, spec: &ChainSpec) -> Result<Signal, String> {
        let log = self.context.log.clone();

        let duration_to_next_slot = self
            .slot_clock
            .duration_to_next_slot()
            .ok_or_else(|| "Unable to determine duration to next slot".to_string())?;

        info!(
            log,
            "Block production service started";
            "next_update_millis" => duration_to_next_slot.as_millis()
        );

        let mut interval = {
            let slot_duration = Duration::from_millis(spec.milliseconds_per_slot);
            // Note: interval_at panics if slot_duration = 0
            interval_at(
                Instant::now() + duration_to_next_slot + TIME_DELAY_FROM_SLOT,
                slot_duration,
            )
        };

        let runtime_handle = self.inner.context.runtime_handle.clone();

        let interval_fut = async move {
            while interval.next().await.is_some() {
                self.do_update().await.ok();
            }
        };

        let (exit_signal, exit_fut) = exit_future::signal();

        let future = futures::future::select(
            Box::pin(interval_fut),
            exit_fut.map(move |_| info!(log, "Shutdown complete")),
        );
        runtime_handle.spawn(future);

        Ok(exit_signal)
    }

    /// Attempt to produce a block for any block producers in the `ValidatorStore`.
    async fn do_update(&self) -> Result<(), ()> {
        let log = &self.context.log;

        let slot = self.slot_clock.now().ok_or_else(move || {
            crit!(log, "Duties manager failed to read slot clock");
        })?;

        trace!(
            log,
            "Block service update started";
            "slot" => slot.as_u64()
        );

        let iter = self.duties_service.block_producers(slot).into_iter();

        if iter.len() == 0 {
            trace!(
                log,
                "No local block proposers for this slot";
                "slot" => slot.as_u64()
            )
        } else if iter.len() > 1 {
            error!(
                log,
                "Multiple block proposers for this slot";
                "action" => "producing blocks for all proposers",
                "num_proposers" => iter.len(),
                "slot" => slot.as_u64(),
            )
        }

        iter.for_each(|validator_pubkey| {
            let service = self.clone();
            let log = log.clone();
            self.inner.context.runtime_handle.spawn(
                service
                    .publish_block(slot, validator_pubkey)
                    .map_err(move |e| {
                        crit!(
                            log,
                            "Error whilst producing block";
                            "message" => e
                        )
                    }),
            );
        });

        Ok(())
    }

    /// Produce a block at the given slot for validator_pubkey
    async fn publish_block(self, slot: Slot, validator_pubkey: PublicKey) -> Result<(), String> {
        let log = &self.context.log;

        let current_slot = self
            .slot_clock
            .now()
            .ok_or_else(|| "Unable to determine current slot from clock".to_string())?;

        let randao_reveal = self
            .validator_store
            .randao_reveal(&validator_pubkey, slot.epoch(E::slots_per_epoch()))
            .ok_or_else(|| "Unable to produce randao reveal".to_string())?;

        let block = self
            .beacon_node
            .http
            .validator()
            .produce_block(slot, randao_reveal)
            .await
            .map_err(|e| format!("Error from beacon node when producing block: {:?}", e))?;

        let signed_block = self
            .validator_store
            .sign_block(&validator_pubkey, block, current_slot)
            .ok_or_else(|| "Unable to sign block".to_string())?;

        let publish_status = self
            .beacon_node
            .http
            .validator()
            .publish_block(signed_block.clone())
            .await
            .map_err(|e| format!("Error from beacon node when publishing block: {:?}", e))?;

        match publish_status {
            PublishStatus::Valid => info!(
                log,
                "Successfully published block";
                "deposits" => signed_block.message.body.deposits.len(),
                "attestations" => signed_block.message.body.attestations.len(),
                "slot" => signed_block.slot().as_u64(),
            ),
            PublishStatus::Invalid(msg) => crit!(
                log,
                "Published block was invalid";
                "message" => msg,
                "slot" => signed_block.slot().as_u64(),
            ),
            PublishStatus::Unknown => crit!(log, "Unknown condition when publishing block"),
        }

        Ok(())
    }
}
