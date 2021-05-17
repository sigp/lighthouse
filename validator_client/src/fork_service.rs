use crate::beacon_node_fallback::{BeaconNodeFallback, RequireSynced};
use crate::http_metrics::metrics;
use environment::RuntimeContext;
use eth2::types::StateId;
use futures::future::FutureExt;
use parking_lot::RwLock;
use slog::{debug, trace};
use slog::{error, Logger};
use slot_clock::SlotClock;
use std::ops::Deref;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use types::{EthSpec, Fork};

/// Delay this period of time after the slot starts. This allows the node to process the new slot.
const TIME_DELAY_FROM_SLOT: Duration = Duration::from_millis(80);

/// Builds a `ForkService`.
pub struct ForkServiceBuilder<T, E: EthSpec> {
    fork: Option<Fork>,
    slot_clock: Option<T>,
    beacon_nodes: Option<Arc<BeaconNodeFallback<T, E>>>,
    log: Option<Logger>,
}

impl<T: SlotClock + 'static, E: EthSpec> ForkServiceBuilder<T, E> {
    pub fn new() -> Self {
        Self {
            fork: None,
            slot_clock: None,
            beacon_nodes: None,
            log: None,
        }
    }

    pub fn fork(mut self, fork: Fork) -> Self {
        self.fork = Some(fork);
        self
    }

    pub fn slot_clock(mut self, slot_clock: T) -> Self {
        self.slot_clock = Some(slot_clock);
        self
    }

    pub fn beacon_nodes(mut self, beacon_nodes: Arc<BeaconNodeFallback<T, E>>) -> Self {
        self.beacon_nodes = Some(beacon_nodes);
        self
    }

    pub fn log(mut self, log: Logger) -> Self {
        self.log = Some(log);
        self
    }

    pub fn build(self) -> Result<ForkService<T, E>, String> {
        Ok(ForkService {
            inner: Arc::new(Inner {
                fork: RwLock::new(self.fork.ok_or("Cannot build ForkService without fork")?),
                slot_clock: self
                    .slot_clock
                    .ok_or("Cannot build ForkService without slot_clock")?,
                beacon_nodes: self
                    .beacon_nodes
                    .ok_or("Cannot build ForkService without beacon_node")?,
                log: self
                    .log
                    .ok_or("Cannot build ForkService without logger")?
                    .clone(),
            }),
        })
    }
}

#[cfg(test)]
#[allow(dead_code)]
impl<E: EthSpec> ForkServiceBuilder<slot_clock::TestingSlotClock, E> {
    pub fn testing_only(spec: types::ChainSpec, log: Logger) -> Self {
        use crate::beacon_node_fallback::CandidateBeaconNode;

        let slot_clock = slot_clock::TestingSlotClock::new(
            types::Slot::new(0),
            std::time::Duration::from_secs(42),
            std::time::Duration::from_secs(42),
        );
        let candidates = vec![CandidateBeaconNode::new(eth2::BeaconNodeHttpClient::new(
            sensitive_url::SensitiveUrl::parse("http://127.0.0.1").unwrap(),
        ))];
        let mut beacon_nodes = BeaconNodeFallback::new(candidates, spec, log.clone());
        beacon_nodes.set_slot_clock(slot_clock);

        Self {
            fork: Some(types::Fork::default()),
            slot_clock: Some(slot_clock::TestingSlotClock::new(
                types::Slot::new(0),
                std::time::Duration::from_secs(42),
                std::time::Duration::from_secs(42),
            )),
            beacon_nodes: Some(Arc::new(beacon_nodes)),
            log: Some(log),
        }
    }
}

/// Helper to minimise `Arc` usage.
pub struct Inner<T, E: EthSpec> {
    fork: RwLock<Fork>,
    beacon_nodes: Arc<BeaconNodeFallback<T, E>>,
    log: Logger,
    slot_clock: T,
}

/// Attempts to download the `Fork` struct from the beacon node at the start of each epoch.
pub struct ForkService<T, E: EthSpec> {
    inner: Arc<Inner<T, E>>,
}

impl<T, E: EthSpec> Clone for ForkService<T, E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T, E: EthSpec> Deref for ForkService<T, E> {
    type Target = Inner<T, E>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl<T: SlotClock + 'static, E: EthSpec> ForkService<T, E> {
    /// Returns the last fork downloaded from the beacon node, if any.
    pub fn fork(&self) -> Fork {
        *self.fork.read()
    }

    /// Starts the service that periodically polls for the `Fork`.
    pub fn start_update_service(self, context: &RuntimeContext<E>) -> Result<(), String> {
        // Run an immediate update before starting the updater service.
        context
            .executor
            .spawn(self.clone().do_update().map(|_| ()), "fork service update");

        let executor = context.executor.clone();
        let log = context.log().clone();
        let spec = E::default_spec();

        let interval_fut = async move {
            loop {
                // Run this poll before the wait, this should hopefully download the fork before the
                // other services need them.
                self.clone().do_update().await.ok();

                if let Some(duration_to_next_epoch) =
                    self.slot_clock.duration_to_next_epoch(E::slots_per_epoch())
                {
                    sleep(duration_to_next_epoch + TIME_DELAY_FROM_SLOT).await;
                } else {
                    error!(log, "Failed to read slot clock");
                    // If we can't read the slot clock, just wait another slot.
                    sleep(Duration::from_secs(spec.seconds_per_slot)).await;
                    continue;
                }
            }
        };

        executor.spawn(interval_fut, "fork_service");

        Ok(())
    }

    /// Attempts to download the `Fork` from the server.
    async fn do_update(self) -> Result<(), ()> {
        let _timer =
            metrics::start_timer_vec(&metrics::FORK_SERVICE_TIMES, &[metrics::FULL_UPDATE]);

        let log = &self.log;
        let fork = self
            .inner
            .beacon_nodes
            .first_success(RequireSynced::No, |beacon_node| async move {
                beacon_node
                    .get_beacon_states_fork(StateId::Head)
                    .await
                    .map_err(|e| {
                        trace!(
                            log,
                            "Fork update failed";
                            "error" => format!("Error retrieving fork: {:?}", e)
                        )
                    })?
                    .ok_or_else(|| {
                        trace!(
                            log,
                            "Fork update failed";
                            "error" => "The beacon head fork is unknown"
                        )
                    })
                    .map(|result| result.data)
            })
            .await
            .map_err(|_| ())?;

        if *(self.fork.read()) != fork {
            *(self.fork.write()) = fork;
        }

        debug!(self.log, "Fork update success");

        // Returning an error will stop the interval. This is not desired, a single failure
        // should not stop all future attempts.
        Ok(())
    }
}
