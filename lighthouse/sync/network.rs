use std::sync::Arc;
use super::db::DB;
use slog::Logger;

use super::network_libp2p::message::{
    NetworkEvent,
    OutgoingMessage,
    NetworkEventType,
};

use super::block::process_unverified_blocks;

use super::wire_protocol::{
    WireMessage,
    WireMessageHeader,
};

use super::futures::sync::mpsc::{
    UnboundedSender,
};

/// Accept a network event and perform all required processing.
///
/// This function should be called whenever an underlying network
/// (e.g., libp2p) has an event to push up to the sync process.
pub fn handle_network_event(
    event: NetworkEvent,
    db: Arc<DB>,
    network_tx: UnboundedSender<OutgoingMessage>,
    log: Logger)
    -> Result<(), ()>
{
        debug!(&log, "";
               "network_event" => format!("{:?}", &event));
        match event.event {
            NetworkEventType::PeerConnect => Ok(()),
            NetworkEventType::PeerDrop => Ok(()),
            NetworkEventType::Message => {
                if let Some(data) = event.data {
                    handle_network_message(
                        data,
                        &db,
                        network_tx,
                        log)
                } else {
                    Ok(())
                }
            }
        }
}

/// Accept a message from the network and perform all required
/// processing.
///
/// This function should be called whenever a peer from a network
/// (e.g., libp2p) has sent a message to us.
fn handle_network_message(
    message: Vec<u8>,
    db: &DB,
    _network_tx: UnboundedSender<OutgoingMessage>,
    log: Logger)
    -> Result<(), ()>
{
    match WireMessage::decode(&message) {
        Ok(msg) => {
            match msg.header {
                WireMessageHeader::Blocks => {
                    process_unverified_blocks(
                        msg.body,
                        db,
                        log
                    );
                    Ok(())
                }
                _ => Ok(())
            }
        }
        Err(_) => {
            return Ok(())  // No need to pass the error back
        }
    }
}
