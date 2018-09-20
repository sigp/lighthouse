use super::tokio;
use super::futures::{ Future, Stream };
use super::futures::sync::mpsc::{
    UnboundedReceiver,
    UnboundedSender,
};
use super::network_libp2p::message::{
    NetworkEvent,
    OutgoingMessage,
};
use super::network::handle_network_event;
use std::sync::Arc;
use super::db::ClientDB;
use slog::Logger;

type NetworkSender = UnboundedSender<OutgoingMessage>;
type NetworkReceiver = UnboundedReceiver<NetworkEvent>;

type SyncSender = UnboundedSender<Vec<u8>>;
type SyncReceiver = UnboundedReceiver<Vec<u8>>;

/// Start a syncing tokio future.
///
/// Uses green-threading to process messages
/// from the network and the RPC and update
/// the state.
pub fn run_sync_future(
    db: Arc<ClientDB>,
    network_tx: NetworkSender,
    network_rx: NetworkReceiver,
    _sync_tx: SyncSender,
    _sync_rx: SyncReceiver,
    log: Logger)
{
    let network_future = {
        network_rx
            .for_each(move |event| {
                handle_network_event(
                    event,
                    db.clone(),
                    network_tx.clone(),
                    log.clone())
            })
            .map_err(|_| panic!("rx failed"))
    };

    tokio::run(network_future);
}
