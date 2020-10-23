use environment::RuntimeContext;
use eth2::{types::StateId, BeaconNodeHttpClient};
use futures::StreamExt;
use parking_lot::RwLock;
use slog::Logger;
use slog::{debug, trace};
use slot_clock::SlotClock;
use std::ops::Deref;
use std::sync::Arc;
use tokio::time::{interval_at, Duration, Instant};
use types::{EthSpec, Fork};

/// Delay this period of time after the slot starts. This allows the node to process the new slot.
const TIME_DELAY_FROM_SLOT: Duration = Duration::from_millis(80);

/// Builds a `ForkService`.
pub struct ForkServiceBuilder<T> {
    fork: Option<Fork>,
    slot_clock: Option<T>,
    beacon_node: Option<BeaconNodeHttpClient>,
    log: Option<Logger>,
}

impl<T: SlotClock + 'static> ForkServiceBuilder<T> {
    pub fn new() -> Self {
        Self {
            fork: None,
            slot_clock: None,
            beacon_node: None,
            log: None,
        }
    }

    pub fn slot_clock(mut self, slot_clock: T) -> Self {
        self.slot_clock = Some(slot_clock);
        self
    }

    pub fn beacon_node(mut self, beacon_node: BeaconNodeHttpClient) -> Self {
        self.beacon_node = Some(beacon_node);
        self
    }

    pub fn log(mut self, log: Logger) -> Self {
        self.log = Some(log);
        self
    }

    pub fn build(self) -> Result<ForkService<T>, String> {
        Ok(ForkService {
            inner: Arc::new(Inner {
                fork: RwLock::new(self.fork),
                slot_clock: self
                    .slot_clock
                    .ok_or_else(|| "Cannot build ForkService without slot_clock")?,
                beacon_node: self
                    .beacon_node
                    .ok_or_else(|| "Cannot build ForkService without beacon_node")?,
                log: self
                    .log
                    .ok_or_else(|| "Cannot build ForkService without logger")?
                    .clone(),
            }),
        })
    }
}

#[cfg(test)]
#[allow(dead_code)]
impl ForkServiceBuilder<slot_clock::TestingSlotClock> {
    pub fn testing_only(log: Logger) -> Self {
        Self {
            fork: Some(types::Fork::default()),
            slot_clock: Some(slot_clock::TestingSlotClock::new(
                types::Slot::new(0),
                std::time::Duration::from_secs(42),
                std::time::Duration::from_secs(42),
            )),
            beacon_node: Some(eth2::BeaconNodeHttpClient::new(
                eth2::Url::parse("http://127.0.0.1").unwrap(),
            )),
            log: Some(log),
        }
    }
}

/// Helper to minimise `Arc` usage.
pub struct Inner<T> {
    fork: RwLock<Option<Fork>>,
    beacon_node: BeaconNodeHttpClient,
    log: Logger,
    slot_clock: T,
}

/// Attempts to download the `Fork` struct from the beacon node at the start of each epoch.
pub struct ForkService<T> {
    inner: Arc<Inner<T>>,
}

impl<T> Clone for ForkService<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T> Deref for ForkService<T> {
    type Target = Inner<T>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl<T: SlotClock + 'static> ForkService<T> {
    /// Returns the last fork downloaded from the beacon node, if any.
    pub fn fork(&self) -> Option<Fork> {
        *self.fork.read()
    }

    /// Starts the service that periodically polls for the `Fork`.
    pub fn start_update_service<E: EthSpec>(
        self,
        context: &RuntimeContext<E>,
    ) -> Result<(), String> {
        let spec = &context.eth2_config.spec;

        let duration_to_next_epoch = self
            .slot_clock
            .duration_to_next_epoch(E::slots_per_epoch())
            .ok_or_else(|| "Unable to determine duration to next epoch".to_string())?;

        let mut interval = {
            let slot_duration = Duration::from_millis(spec.milliseconds_per_slot);
            // Note: interval_at panics if `slot_duration * E::slots_per_epoch()` = 0
            interval_at(
                Instant::now() + duration_to_next_epoch + TIME_DELAY_FROM_SLOT,
                slot_duration * E::slots_per_epoch() as u32,
            )
        };

        // Run an immediate update before starting the updater service.
        context
            .executor
            .runtime_handle()
            .spawn(self.clone().do_update());

        let executor = context.executor.clone();

        let interval_fut = async move {
            while interval.next().await.is_some() {
                self.clone().do_update().await.ok();
            }
        };

        executor.spawn(interval_fut, "fork_service");

        Ok(())
    }

    /// Attempts to download the `Fork` from the server.
    async fn do_update(self) -> Result<(), ()> {
        let fork = self
            .inner
            .beacon_node
            .get_beacon_states_fork(StateId::Head)
            .await
            .map_err(|e| {
                trace!(
                    self.log,
                    "Fork update failed";
                    "error" => format!("Error retrieving fork: {:?}", e)
                )
            })?
            .ok_or_else(|| {
                trace!(
                    self.log,
                    "Fork update failed";
                    "error" => "The beacon head fork is unknown"
                )
            })?
            .data;

        if self.fork.read().as_ref() != Some(&fork) {
            *(self.fork.write()) = Some(fork);
        }

        debug!(self.log, "Fork update success");

        // Returning an error will stop the interval. This is not desired, a single failure
        // should not stop all future attempts.
        Ok(())
    }
}
