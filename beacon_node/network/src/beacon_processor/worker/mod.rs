use crate::{service::NetworkMessage, sync::SyncMessage};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use slog::{error, Logger};
use std::sync::Arc;
use tokio::sync::mpsc;

mod gossip_methods;
mod rpc_methods;
mod sync_methods;

pub use sync_methods::ProcessId;

pub(crate) const FUTURE_SLOT_TOLERANCE: u64 = 1;

/// Contains the context necessary to import blocks, attestations, etc to the beacon chain.
pub struct Worker<T: BeaconChainTypes> {
    pub chain: Arc<BeaconChain<T>>,
    pub network_tx: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
    pub sync_tx: mpsc::UnboundedSender<SyncMessage<T::EthSpec>>,
    pub log: Logger,
}

impl<T: BeaconChainTypes> Worker<T> {
    /// Send a message to `sync_tx`.
    ///
    /// Creates a log if there is an internal error.
    fn send_sync_message(&self, message: SyncMessage<T::EthSpec>) {
        self.sync_tx.send(message).unwrap_or_else(|e| {
            error!(self.log, "Could not send message to the sync service";
                "error" => %e)
        });
    }

    /// Send a message to `network_tx`.
    ///
    /// Creates a log if there is an internal error.
    fn send_network_message(&self, message: NetworkMessage<T::EthSpec>) {
        self.network_tx.send(message).unwrap_or_else(|e| {
            error!(self.log, "Could not send message to the network service";
                "error" => %e)
        });
    }
}
