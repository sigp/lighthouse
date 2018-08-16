extern crate futures;
extern crate slog;
extern crate tokio;

use self::futures::sync::mpsc::{
    UnboundedReceiver,
    UnboundedSender,
};
use self::futures::Stream;
use self::tokio::timer::Interval;
use self::tokio::prelude::*;
use std::sync::{ RwLock, Arc };
use super::network_libp2p::message::{
    NetworkEvent,
    OutgoingMessage,
};
use super::db::DB;
use slog::Logger;

use std::time::{ Duration, Instant };

type NetworkSender = UnboundedSender<OutgoingMessage>;
type NetworkReceiver = UnboundedReceiver<NetworkEvent>;

type SyncSender = UnboundedSender<Vec<u8>>;
type SyncReceiver = UnboundedReceiver<Vec<u8>>;

pub fn start_sync(
    _db: Arc<RwLock<DB>>,
    network_tx: NetworkSender,
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

    let poll_future = Interval::new(Instant::now(), Duration::from_secs(2))
        .for_each(move |_| {
            let msg = OutgoingMessage {
                peer: None,
                data: vec![42, 42, 42]
            };
            network_tx.unbounded_send(msg);
            Ok(())
        })
        .map_err(|_| panic!("send failed"));

    let sync_future = poll_future
        .select(rx_future).map_err(|(err, _)| err)
        .and_then(|((), n)| n);

    tokio::run(sync_future);
}
