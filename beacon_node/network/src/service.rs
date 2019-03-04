use crate::error;
use crate::message_handler::{HandlerMessage, MessageHandler};
use crate::messages::{NetworkMessage, NodeMessage};
use crate::NetworkConfig;
use crossbeam_channel::{unbounded as channel, Sender};
use futures::sync::oneshot;
use libp2p::Service as LibP2PService;
use slog::{debug, info, o, trace, warn, Logger};
use std::sync::{Arc, Mutex};

/// Service that handles communication between internal services and the libp2p network service.
pub struct Service {
    //libp2p_service: Arc<Mutex<LibP2PService>>,
//libp2p_thread: oneshot::Sender<()>,
//message_handler: MessageHandler,
//message_handler_send: Sender<HandlerMessage>,
}

impl Service {
    pub fn new(
        config: NetworkConfig,
        log: slog::Logger,
    ) -> error::Result<(Arc<Self>, Sender<NetworkMessage>)> {
        debug!(log, "Service starting");
        let (network_send, network_recv) = channel::<NetworkMessage>();

        // launch message handler thread
        let message_handler_log = log.new(o!("Service" => "MessageHandler"));
        let message_handler_send = MessageHandler::new(message_handler_log);

        // launch libp2p service
        let libp2p_log = log.new(o!("Service" => "Libp2p"));
        let libp2p_service = LibP2PService::new(libp2p_log);

        // TODO: Spawn thread to handle libp2p messages and pass to message handler thread.

        let network = Service {};

        Ok((Arc::new(network), network_send))
    }
}
