use crate::error;
use crate::service::{NetworkMessage, OutgoingMessage};
use crate::sync::SimpleSync;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::rpc::methods::*;
use eth2_libp2p::{
    behaviour::PubsubMessage,
    rpc::{RPCError, RPCErrorResponse, RPCRequest, RPCResponse, RequestId},
    PeerId, RPCEvent,
};
use futures::future::Future;
use futures::stream::Stream;
use slog::{debug, trace, warn};
use ssz::{Decode, DecodeError};
use std::sync::Arc;
use tokio::sync::mpsc;
use types::{Attestation, AttesterSlashing, BeaconBlock, ProposerSlashing, VoluntaryExit};

/// Handles messages received from the network and client and organises syncing.
pub struct MessageHandler<T: BeaconChainTypes> {
    /// Currently loaded and initialised beacon chain.
    _chain: Arc<BeaconChain<T>>,
    /// The syncing framework.
    sync: SimpleSync<T>,
    /// The `MessageHandler` logger.
    log: slog::Logger,
}

/// Types of messages the handler can receive.
#[derive(Debug)]
pub enum HandlerMessage {
    /// We have initiated a connection to a new peer.
    PeerDialed(PeerId),
    /// Peer has disconnected,
    PeerDisconnected(PeerId),
    /// An RPC response/request has been received.
    RPC(PeerId, RPCEvent),
    /// A gossip message has been received.
    PubsubMessage(PeerId, PubsubMessage),
}

impl<T: BeaconChainTypes + 'static> MessageHandler<T> {
    /// Initializes and runs the MessageHandler.
    pub fn spawn(
        beacon_chain: Arc<BeaconChain<T>>,
        network_send: mpsc::UnboundedSender<NetworkMessage>,
        executor: &tokio::runtime::TaskExecutor,
        log: slog::Logger,
    ) -> error::Result<mpsc::UnboundedSender<HandlerMessage>> {
        trace!(log, "Service starting");

        let (handler_send, handler_recv) = mpsc::unbounded_channel();
        // Initialise sync and begin processing in thread
        let sync = SimpleSync::new(beacon_chain.clone(), network_send, &log);

        // generate the Message handler
        let mut handler = MessageHandler {
            _chain: beacon_chain.clone(),
            sync,
            log: log.clone(),
        };

        // spawn handler task and move the message handler instance into the spawned thread
        executor.spawn(
            handler_recv
                .for_each(move |msg| Ok(handler.handle_message(msg)))
                .map_err(move |_| {
                    debug!(log, "Network message handler terminated.");
                }),
        );

        Ok(handler_send)
    }

    /// Handle all messages incoming from the network service.
    fn handle_message(&mut self, message: HandlerMessage) {
        match message {
            // we have initiated a connection to a peer
            HandlerMessage::PeerDialed(peer_id) => {
                self.sync.on_connect(peer_id);
            }
            // A peer has disconnected
            HandlerMessage::PeerDisconnected(peer_id) => {
                self.sync.on_disconnect(peer_id);
            }
            // An RPC message request/response has been received
            HandlerMessage::RPC(peer_id, rpc_event) => {
                self.handle_rpc_message(peer_id, rpc_event);
            }
            // An RPC message request/response has been received
            HandlerMessage::PubsubMessage(peer_id, gossip) => {
                self.handle_gossip(peer_id, gossip);
            }
        }
    }

    /* RPC - Related functionality */

    /// Handle RPC messages
    fn handle_rpc_message(&mut self, peer_id: PeerId, rpc_message: RPCEvent) {
        match rpc_message {
            RPCEvent::Request(id, req) => self.handle_rpc_request(peer_id, id, req),
            RPCEvent::Response(id, resp) => self.handle_rpc_response(peer_id, id, resp),
            RPCEvent::Error(id, error) => self.handle_rpc_error(peer_id, id, error),
        }
    }

    /// A new RPC request has been received from the network.
    fn handle_rpc_request(&mut self, peer_id: PeerId, request_id: RequestId, request: RPCRequest) {
        match request {
            RPCRequest::Hello(hello_message) => {
                self.sync
                    .on_hello_request(peer_id, request_id, hello_message)
            }
            RPCRequest::Goodbye(goodbye_reason) => {
                debug!(
                    self.log, "PeerGoodbye";
                    "peer" => format!("{:?}", peer_id),
                    "reason" => format!("{:?}", goodbye_reason),
                );
                self.sync.on_disconnect(peer_id);
            }
            RPCRequest::BeaconBlocks(request) => self
                .sync
                .on_beacon_blocks_request(peer_id, request_id, request),
            RPCRequest::RecentBeaconBlocks(request) => self
                .sync
                .on_recent_beacon_blocks_request(peer_id, request_id, request),
        }
    }

    /// An RPC response has been received from the network.
    // we match on id and ignore responses past the timeout.
    fn handle_rpc_response(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        error_response: RPCErrorResponse,
    ) {
        // an error could have occurred.
        match error_response {
            RPCErrorResponse::InvalidRequest(error) => {
                warn!(self.log, "Peer indicated invalid request";"peer_id" => format!("{:?}", peer_id), "error" => error.as_string())
            }
            RPCErrorResponse::ServerError(error) => {
                warn!(self.log, "Peer internal server error";"peer_id" => format!("{:?}", peer_id), "error" => error.as_string())
            }
            RPCErrorResponse::Unknown(error) => {
                warn!(self.log, "Unknown peer error";"peer" => format!("{:?}", peer_id), "error" => error.as_string())
            }
            RPCErrorResponse::Success(response) => {
                match response {
                    RPCResponse::Hello(hello_message) => {
                        self.sync.on_hello_response(peer_id, hello_message);
                    }
                    RPCResponse::BeaconBlocks(response) => {
                        match self.decode_beacon_blocks(&response) {
                            Ok(beacon_blocks) => {
                                self.sync.on_beacon_blocks_response(
                                    peer_id,
                                    request_id,
                                    beacon_blocks,
                                );
                            }
                            Err(e) => {
                                // TODO: Down-vote Peer
                                warn!(self.log, "Peer sent invalid BEACON_BLOCKS response";"peer" => format!("{:?}", peer_id), "error" => format!("{:?}", e));
                            }
                        }
                    }
                    RPCResponse::RecentBeaconBlocks(response) => {
                        match self.decode_beacon_blocks(&response) {
                            Ok(beacon_blocks) => {
                                self.sync.on_recent_beacon_blocks_response(
                                    peer_id,
                                    request_id,
                                    beacon_blocks,
                                );
                            }
                            Err(e) => {
                                // TODO: Down-vote Peer
                                warn!(self.log, "Peer sent invalid BEACON_BLOCKS response";"peer" => format!("{:?}", peer_id), "error" => format!("{:?}", e));
                            }
                        }
                    }
                }
            }
        }
    }

    /// Handle various RPC errors
    fn handle_rpc_error(&mut self, peer_id: PeerId, request_id: RequestId, error: RPCError) {
        //TODO: Handle error correctly
        warn!(self.log, "RPC Error"; "Peer" => format!("{:?}", peer_id), "request_id" => format!("{}", request_id), "Error" => format!("{:?}", error));
    }

    /// Handle RPC messages
    fn handle_gossip(&mut self, peer_id: PeerId, gossip_message: PubsubMessage) {
        match gossip_message {
            PubsubMessage::Block(message) => match self.decode_gossip_block(message) {
                Ok(block) => {
                    let _should_forward_on = self.sync.on_block_gossip(peer_id, block);
                }
                Err(e) => {
                    debug!(self.log, "Invalid gossiped beacon block"; "peer_id" => format!("{}", peer_id), "Error" => format!("{:?}", e));
                }
            },
            PubsubMessage::Attestation(message) => match self.decode_gossip_attestation(message) {
                Ok(attestation) => self.sync.on_attestation_gossip(peer_id, attestation),
                Err(e) => {
                    debug!(self.log, "Invalid gossiped attestation"; "peer_id" => format!("{}", peer_id), "Error" => format!("{:?}", e));
                }
            },
            PubsubMessage::VoluntaryExit(message) => match self.decode_gossip_exit(message) {
                Ok(_exit) => {
                    // TODO: Handle exits
                    debug!(self.log, "Received a voluntary exit"; "peer_id" => format!("{}", peer_id) );
                }
                Err(e) => {
                    debug!(self.log, "Invalid gossiped exit"; "peer_id" => format!("{}", peer_id), "Error" => format!("{:?}", e));
                }
            },
            PubsubMessage::ProposerSlashing(message) => {
                match self.decode_gossip_proposer_slashing(message) {
                    Ok(_slashing) => {
                        // TODO: Handle proposer slashings
                        debug!(self.log, "Received a proposer slashing"; "peer_id" => format!("{}", peer_id) );
                    }
                    Err(e) => {
                        debug!(self.log, "Invalid gossiped proposer slashing"; "peer_id" => format!("{}", peer_id), "Error" => format!("{:?}", e));
                    }
                }
            }
            PubsubMessage::AttesterSlashing(message) => {
                match self.decode_gossip_attestation_slashing(message) {
                    Ok(_slashing) => {
                        // TODO: Handle attester slashings
                        debug!(self.log, "Received an attester slashing"; "peer_id" => format!("{}", peer_id) );
                    }
                    Err(e) => {
                        debug!(self.log, "Invalid gossiped attester slashing"; "peer_id" => format!("{}", peer_id), "Error" => format!("{:?}", e));
                    }
                }
            }
            PubsubMessage::Unknown(message) => {
                // Received a message from an unknown topic. Ignore for now
                debug!(self.log, "Unknown Gossip Message"; "peer_id" => format!("{}", peer_id), "Message" => format!("{:?}", message));
            }
        }
    }

    /* Decoding of gossipsub objects from the network.
     *
     * The decoding is done in the message handler as it has access to to a `BeaconChain` and can
     * therefore apply more efficient logic in decoding and verification.
     *
     * TODO: Apply efficient decoding/verification of these objects
     */

    /* Gossipsub Domain Decoding */
    // Note: These are not generics as type-specific verification will need to be applied.
    fn decode_gossip_block(
        &self,
        beacon_block: Vec<u8>,
    ) -> Result<BeaconBlock<T::EthSpec>, DecodeError> {
        //TODO: Apply verification before decoding.
        BeaconBlock::from_ssz_bytes(&beacon_block)
    }

    fn decode_gossip_attestation(
        &self,
        beacon_block: Vec<u8>,
    ) -> Result<Attestation<T::EthSpec>, DecodeError> {
        //TODO: Apply verification before decoding.
        Attestation::from_ssz_bytes(&beacon_block)
    }

    fn decode_gossip_exit(&self, voluntary_exit: Vec<u8>) -> Result<VoluntaryExit, DecodeError> {
        //TODO: Apply verification before decoding.
        VoluntaryExit::from_ssz_bytes(&voluntary_exit)
    }

    fn decode_gossip_proposer_slashing(
        &self,
        proposer_slashing: Vec<u8>,
    ) -> Result<ProposerSlashing, DecodeError> {
        //TODO: Apply verification before decoding.
        ProposerSlashing::from_ssz_bytes(&proposer_slashing)
    }

    fn decode_gossip_attestation_slashing(
        &self,
        attester_slashing: Vec<u8>,
    ) -> Result<AttesterSlashing<T::EthSpec>, DecodeError> {
        //TODO: Apply verification before decoding.
        AttesterSlashing::from_ssz_bytes(&attester_slashing)
    }

    /* Req/Resp Domain Decoding  */

    /// Verifies and decodes an ssz-encoded list of `BeaconBlock`s. This list may contain empty
    /// entries encoded with an SSZ NULL.
    fn decode_beacon_blocks(
        &self,
        beacon_blocks: &[u8],
    ) -> Result<Vec<BeaconBlock<T::EthSpec>>, DecodeError> {
        //TODO: Implement faster block verification before decoding entirely
        Vec::from_ssz_bytes(&beacon_blocks)
    }
}
