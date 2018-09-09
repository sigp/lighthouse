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
use std::sync::{ RwLock, Arc };
use super::db::DB;
use slog::Logger;

type NetworkSender = UnboundedSender<OutgoingMessage>;
type NetworkReceiver = UnboundedReceiver<NetworkEvent>;

type SyncSender = UnboundedSender<Vec<u8>>;
type SyncReceiver = UnboundedReceiver<Vec<u8>>;

/// Start a syncing tokio future.
///
/// This is effectively a stub function being
/// used to test network functionality.
///
/// Expect a full re-write.
pub fn run_sync_future(
    db: Arc<RwLock<DB>>,
    network_tx: NetworkSender,
    network_rx: NetworkReceiver,
    _sync_tx: SyncSender,
    _sync_rx: SyncReceiver,
    log: Logger) {
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

    /*
     * This is an unfinished stub function.
     */

    tokio::run(network_future);
}
