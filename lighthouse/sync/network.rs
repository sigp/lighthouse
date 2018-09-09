use std::sync::{ RwLock, Arc };
use super::db::DB;
use slog::Logger;

use super::network_libp2p::message::{
    NetworkEvent,
    OutgoingMessage,
    NetworkEventType,
};

use super::futures::sync::mpsc::{
    UnboundedSender,
};

pub fn handle_network_event(
    event: NetworkEvent,
    db: Arc<RwLock<DB>>,
    network_tx: UnboundedSender<OutgoingMessage>,
    log: Logger)
    -> Result<(), ()>
{
        match event.event {
            NetworkEventType::PeerConnect => Ok(()),
            NetworkEventType::PeerDrop => Ok(()),
            NetworkEventType::Message => handle_network_message(
                event.data,
                db,
                network_tx,
                log
            )
        }
}

fn handle_network_message(
    message: Option<Vec<u8>>,
    _db: Arc<RwLock<DB>>,
    _network_tx: UnboundedSender<OutgoingMessage>,
    log: Logger)
    -> Result<(), ()>
{
    debug!(&log, "";
           "network_msg" => format!("{:?}", message));
    Ok(())
}
