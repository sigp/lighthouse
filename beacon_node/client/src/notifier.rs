use crate::Client;
use exit_future::Exit;
use futures::{Future, Stream};
use slog::{debug, o, warn};
use std::time::{Duration, Instant};
use store::Store;
use tokio::runtime::TaskExecutor;
use tokio::timer::Interval;
use types::EthSpec;

/// The interval between heartbeat events.
pub const HEARTBEAT_INTERVAL_SECONDS: u64 = 15;

/// Create a warning log whenever the peer count is at or below this value.
pub const WARN_PEER_COUNT: usize = 1;

/// Spawns a thread that can be used to run code periodically, on `HEARTBEAT_INTERVAL_SECONDS`
/// durations.
///
/// Presently unused, but remains for future use.
pub fn run<S, E>(client: &Client<S, E>, executor: TaskExecutor, exit: Exit)
where
    S: Store + Clone + 'static,
    E: EthSpec,
{
    // notification heartbeat
    let interval = Interval::new(
        Instant::now(),
        Duration::from_secs(HEARTBEAT_INTERVAL_SECONDS),
    );

    let log = client.log.new(o!("Service" => "Notifier"));

    let libp2p = client.network.libp2p_service();

    let heartbeat = move |_| {
        // Number of libp2p (not discv5) peers connected.
        //
        // Panics if libp2p is poisoned.
        let connected_peer_count = libp2p.lock().swarm.connected_peers();

        debug!(log, "Connected peer status"; "peer_count" => connected_peer_count);

        if connected_peer_count <= WARN_PEER_COUNT {
            warn!(log, "Low peer count"; "peer_count" => connected_peer_count);
        }

        Ok(())
    };

    // map error and spawn
    let err_log = client.log.clone();
    let heartbeat_interval = interval
        .map_err(move |e| debug!(err_log, "Timer error {}", e))
        .for_each(heartbeat);

    executor.spawn(exit.until(heartbeat_interval).map(|_| ()));
}
