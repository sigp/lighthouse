extern crate futures;
extern crate slog;
extern crate tokio;

use self::futures::sync::mpsc::{
    UnboundedReceiver,
    UnboundedSender,
};
use self::tokio::prelude::*;
use std::sync::{ RwLock, Arc };
use super::network_libp2p::message::{
    NetworkEvent,
    OutgoingMessage,
};
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
pub fn start_sync(
    _db: Arc<RwLock<DB>>,
    _network_tx: NetworkSender,
    network_rx: NetworkReceiver,
    _sync_tx: SyncSender,
    _sync_rx: SyncReceiver,
    log: Logger) {
    let rx_future = network_rx
        .for_each(move |event| {
            debug!(&log, "Sync receive";
                   "msg" => format!("{:?}", event));
            Ok(())
        })
        .map_err(|_| panic!("rx failed"));

    /*
     * This is an unfinished stub function.
     */

    tokio::run(rx_future);
}
