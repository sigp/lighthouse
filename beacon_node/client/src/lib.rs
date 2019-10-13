extern crate slog;

mod config;

pub mod builder;
pub mod error;
pub mod notifier;

use beacon_chain::{
    builder::BeaconChainBuilder, lmd_ghost::ThreadSafeReducedTree, slot_clock::SystemTimeSlotClock,
    store::Store, test_utils::generate_deterministic_keypairs, BeaconChain,
};
use exit_future::Signal;
use futures::{future::Future, Stream};
use network::Service as NetworkService;
use rest_api::NetworkInfo;
use slog::{crit, error, info, o};
use std::sync::Arc;

pub use beacon_chain::{BeaconChainTypes, Eth1ChainBackend, InteropEth1ChainBackend};
pub use config::{Config as ClientConfig, Eth1BackendMethod};
pub use eth2_config::Eth2Config;

/// The core "beacon node" client.
///
/// Holds references to running services, cleanly shutting them down when it is dropped.
pub struct Client<T: BeaconChainTypes> {
    beacon_chain: Option<Arc<BeaconChain<T>>>,
    libp2p_network: Option<Arc<NetworkService<T>>>,
    exit_signals: Vec<Signal>,
}

impl<T: BeaconChainTypes> Drop for Client<T> {
    fn drop(&mut self) {
        if let Some(beacon_chain) = self.beacon_chain {
            let _result = beacon_chain.persist();
        }
    }
}

fn log_new_slot<T: BeaconChainTypes>(chain: &Arc<BeaconChain<T>>, log: &slog::Logger) {
    let best_slot = chain.head().beacon_block.slot;
    let latest_block_root = chain.head().beacon_block_root;

    if let Ok(current_slot) = chain.slot() {
        info!(
            log,
            "Slot start";
            "skip_slots" => current_slot.saturating_sub(best_slot),
            "best_block_root" => format!("{}", latest_block_root),
            "best_block_slot" => best_slot,
            "slot" => current_slot,
        )
    } else {
        error!(
            log,
            "Beacon chain running whilst slot clock is unavailable."
        );
    };
}
