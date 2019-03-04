use crate::Client;
use crate::ClientTypes;
use db::ClientDB;
use exit_future::Exit;
use fork_choice::ForkChoice;
use futures::{Future, Stream};
use slog::{debug, info};
use slot_clock::SlotClock;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::runtime::TaskExecutor;
use tokio::timer::Interval;

/// Thread that monitors the client and reports useful statistics to the user.

pub fn run<T: ClientTypes>(client: &Client<T>, executor: TaskExecutor, exit: Exit) {
    // notification heartbeat
    let interval = Interval::new(Instant::now(), Duration::from_secs(5));

    let log = client.log.new(o!("Service" => "Notifier"));

    // build heartbeat logic here
    let heartbeat = move |_| {
        info!(log, "Temp heartbeat output");
        Ok(())
    };

    // map error and spawn
    let log = client.logger();
    let heartbeat_interval = interval
        .map_err(move |e| debug!(log, "Timer error {}", e))
        .for_each(heartbeat);

    executor.spawn(exit.until(heartbeat_interval).map(|_| ()));
}
