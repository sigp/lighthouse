use crate::Client;
use beacon_chain::BeaconChainTypes;
use exit_future::Exit;
use futures::{Future, Stream};
use slog::{debug, o};
use std::time::{Duration, Instant};
use tokio::runtime::TaskExecutor;
use tokio::timer::Interval;

/// The interval between heartbeat events.
pub const HEARTBEAT_INTERVAL_SECONDS: u64 = 5;

/// Spawns a thread that can be used to run code periodically, on `HEARTBEAT_INTERVAL_SECONDS`
/// durations.
///
/// Presently unused, but remains for future use.
pub fn run<T: BeaconChainTypes + Send + Sync + 'static>(
    client: &Client<T>,
    executor: TaskExecutor,
    exit: Exit,
) {
    // notification heartbeat
    let interval = Interval::new(
        Instant::now(),
        Duration::from_secs(HEARTBEAT_INTERVAL_SECONDS),
    );

    let _log = client.log.new(o!("Service" => "Notifier"));

    let heartbeat = |_| {
        // There is not presently any heartbeat logic.
        //
        // We leave this function empty for future use.
        Ok(())
    };

    // map error and spawn
    let log = client.log.clone();
    let heartbeat_interval = interval
        .map_err(move |e| debug!(log, "Timer error {}", e))
        .for_each(heartbeat);

    executor.spawn(exit.until(heartbeat_interval).map(|_| ()));
}
