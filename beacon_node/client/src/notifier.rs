use crate::Client;
use beacon_chain::BeaconChainTypes;
use exit_future::Exit;
use futures::{Future, Stream};
use slog::{debug, o};
use std::time::{Duration, Instant};
use tokio::runtime::TaskExecutor;
use tokio::timer::Interval;

/// The interval between heartbeat events.
pub const HEARTBEAT_INTERVAL_SECONDS: u64 = 15;

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

    let log = client.log.new(o!("Service" => "Notifier"));

    let libp2p = client.network.libp2p_service();

    let heartbeat = move |_| {
        // Notify the number of connected nodes
        // Panic if libp2p is poisoned
        debug!(log, ""; "Connected Peers" => libp2p.lock().swarm.connected_peers());

        Ok(())
    };

    // map error and spawn
    let err_log = client.log.clone();
    let heartbeat_interval = interval
        .map_err(move |e| debug!(err_log, "Timer error {}", e))
        .for_each(heartbeat);

    executor.spawn(exit.until(heartbeat_interval).map(|_| ()));
}
