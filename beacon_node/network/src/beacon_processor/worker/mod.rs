use crate::{service::NetworkMessage, sync::SyncMessage};
use beacon_chain::BeaconChainTypes;
use slog::debug;

mod gossip_methods;
mod rpc_methods;
mod sync_methods;

pub use gossip_methods::{GossipAggregatePackage, GossipAttestationPackage};

use super::NetworkBeaconProcessor;

pub(crate) const FUTURE_SLOT_TOLERANCE: u64 = 1;

impl<T: BeaconChainTypes> NetworkBeaconProcessor<T> {
    /// Send a message to `sync_tx`.
    ///
    /// Creates a log if there is an internal error.
    fn send_sync_message(&self, message: SyncMessage<T::EthSpec>) {
        self.sync_tx.send(message).unwrap_or_else(|e| {
            debug!(self.log, "Could not send message to the sync service";
                   "error" => %e)
        });
    }

    /// Send a message to `network_tx`.
    ///
    /// Creates a log if there is an internal error.
    fn send_network_message(&self, message: NetworkMessage<T::EthSpec>) {
        self.network_tx.send(message).unwrap_or_else(|e| {
            debug!(self.log, "Could not send message to the network service. Likely shutdown";
                "error" => %e)
        });
    }
}
