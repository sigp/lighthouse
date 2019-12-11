use environment::RuntimeContext;
use exit_future::Signal;
use futures::{Future, Stream};
use parking_lot::RwLock;
use remote_beacon_node::RemoteBeaconNode;
use slog::{crit, info, trace};
use slot_clock::SlotClock;
use std::ops::Deref;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::timer::Interval;
use types::{ChainSpec, EthSpec, Fork};

/// Delay this period of time after the slot starts. This allows the node to process the new slot.
const TIME_DELAY_FROM_SLOT: Duration = Duration::from_millis(80);

/// Builds a `ForkService`.
pub struct ForkServiceBuilder<T, E: EthSpec> {
    fork: Option<Fork>,
    slot_clock: Option<T>,
    beacon_node: Option<RemoteBeaconNode<E>>,
    context: Option<RuntimeContext<E>>,
}

impl<T: SlotClock + 'static, E: EthSpec> ForkServiceBuilder<T, E> {
    pub fn new() -> Self {
        Self {
            fork: None,
            slot_clock: None,
            beacon_node: None,
            context: None,
        }
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

    pub fn build(self) -> Result<ForkService<T, E>, String> {
        Ok(ForkService {
            inner: Arc::new(Inner {
                fork: RwLock::new(self.fork),
                slot_clock: self
                    .slot_clock
                    .ok_or_else(|| "Cannot build ForkService without slot_clock")?,
                beacon_node: self
                    .beacon_node
                    .ok_or_else(|| "Cannot build ForkService without beacon_node")?,
                context: self
                    .context
                    .ok_or_else(|| "Cannot build ForkService without runtime_context")?,
            }),
        })
    }
}

/// Helper to minimise `Arc` usage.
pub struct Inner<T, E: EthSpec> {
    fork: RwLock<Option<Fork>>,
    beacon_node: RemoteBeaconNode<E>,
    context: RuntimeContext<E>,
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
    pub fn fork(&self) -> Option<Fork> {
        self.fork.read().clone()
    }

    /// Starts the service that periodically polls for the `Fork`.
    pub fn start_update_service(&self, spec: &ChainSpec) -> Result<Signal, String> {
        let log = self.context.log.clone();

        let duration_to_next_epoch = self
            .slot_clock
            .duration_to_next_epoch(E::slots_per_epoch())
            .ok_or_else(|| "Unable to determine duration to next epoch".to_string())?;

        let interval = {
            let slot_duration = Duration::from_millis(spec.milliseconds_per_slot);
            Interval::new(
                Instant::now() + duration_to_next_epoch + TIME_DELAY_FROM_SLOT,
                slot_duration * E::slots_per_epoch() as u32,
            )
        };

        let (exit_signal, exit_fut) = exit_future::signal();
        let service = self.clone();
        let log_1 = log.clone();
        let log_2 = log.clone();

        // Run an immediate update before starting the updater service.
        self.context.executor.spawn(service.clone().do_update());

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
                        .for_each(move |_| service.do_update().then(|_| Ok(()))),
                )
                .map(move |_| info!(log_2, "Shutdown complete")),
        );

        Ok(exit_signal)
    }

    /// Attempts to download the `Fork` from the server.
    fn do_update(&self) -> impl Future<Item = (), Error = ()> {
        let service_1 = self.clone();
        let log_1 = service_1.context.log.clone();
        let log_2 = service_1.context.log.clone();

        self.inner
            .beacon_node
            .http
            .beacon()
            .get_fork()
            .map(move |fork| *(service_1.fork.write()) = Some(fork))
            .map(move |_| trace!(log_1, "Fork update success"))
            .map_err(move |e| {
                trace!(
                    log_2,
                    "Fork update failed";
                    "error" => format!("Error retrieving fork: {:?}", e)
                )
            })
            // Returning an error will stop the interval. This is not desired, a single failure
            // should not stop all future attempts.
            .then(|_| Ok(()))
    }
}
