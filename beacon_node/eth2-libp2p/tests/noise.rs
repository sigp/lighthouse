#![cfg(test)]
use eth2_libp2p::*;
use futures::prelude::*;
use slog::{info, Level};
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;
use tokio::prelude::*;

mod common;

/// Test if the encryption falls back to secio if noise isn't available
#[test]
fn test_secio_noise_fallback() {
    // set up the logging. The level and enabled logging or not
    let log_level = Level::Trace;
    let enable_logging = false;

    let log = common::build_log(log_level, enable_logging);

    let noisy_config = common::build_config(56010, vec![], None);
    let mut noisy_node = Service::new(&noisy_config, log.clone())
        .expect("should build a libp2p instance")
        .1;

    let mut secio_config = common::build_config(56011, vec![common::get_enr(&noisy_node)], None);

    secio_config.has_noise_support = false;
    let mut secio_node = Service::new(&secio_config, log.clone())
        .expect("should build a libp2p instance")
        .1;

    let secio_log = log.clone();

    let noisy_future = future::poll_fn(move || -> Poll<bool, ()> {
        loop {
            match noisy_node.poll().unwrap() {
                _ => return Ok(Async::NotReady),
            }
        }
    });

    let secio_future = future::poll_fn(move || -> Poll<bool, ()> {
        loop {
            match secio_node.poll().unwrap() {
                Async::Ready(Some(Libp2pEvent::PeerDialed(peer_id))) => {
                    // secio node negotiated a secio transport with
                    // the noise compatible node
                    info!(secio_log, "Connected to peer {}", peer_id);
                    return Ok(Async::Ready(true));
                }
                _ => return Ok(Async::NotReady),
            }
        }
    });

    // execute the futures and check the result
    let test_result = Arc::new(AtomicBool::new(false));
    let error_result = test_result.clone();
    let thread_result = test_result.clone();
    tokio::run(
        noisy_future
            .select(secio_future)
            .timeout(Duration::from_millis(1000))
            .map_err(move |_| error_result.store(false, Relaxed))
            .map(move |result| {
                thread_result.store(result.0, Relaxed);
            }),
    );
    assert!(test_result.load(Relaxed));
}
