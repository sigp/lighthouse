use crate::Client;
use crate::ClientTypes;
use exit_future::Exit;
use futures::{Future, Stream};
use slog::{debug, o};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::runtime::TaskExecutor;
use tokio::timer::Interval;

/// Thread that monitors the client and reports useful statistics to the user.

pub fn run<T: ClientTypes>(client: &Client<T>, executor: TaskExecutor, exit: Exit) {
    // notification heartbeat
    let interval = Interval::new(Instant::now(), Duration::from_secs(5));

    let _log = client.log.new(o!("Service" => "Notifier"));

    // TODO: Debugging only
    let counter = Arc::new(Mutex::new(0));
    let network = client.network.clone();

    // build heartbeat logic here
    let heartbeat = move |_| {
        //debug!(log, "Temp heartbeat output");
        //TODO: Remove this logic. Testing only
        let mut count = counter.lock().unwrap();
        *count += 1;

        if *count % 5 == 0 {
            //            debug!(log, "Sending Message");
            network.send_message();
        }

        Ok(())
    };

    // map error and spawn
    let log = client.log.clone();
    let heartbeat_interval = interval
        .map_err(move |e| debug!(log, "Timer error {}", e))
        .for_each(heartbeat);

    executor.spawn(exit.until(heartbeat_interval).map(|_| ()));
}
