//! This module handles incoming network messages.
//!
//! It routes the messages to appropriate services.
//! It handles requests at the application layer in its associated processor and directs
//! syncing-related responses to the Sync manager.
#![allow(clippy::unit_arg)]

pub mod processor;

use crate::error;
use crate::service::NetworkMessage;
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockError};
use eth2_libp2p::{
    rpc::{RPCError, RequestId},
    MessageId, NetworkGlobals, PeerId, PeerRequestId, PubsubMessage, Request, Response,
};
use futures::prelude::*;
use processor::Processor;
use slog::{debug, info, o, trace, warn};
use std::sync::Arc;
use tokio::sync::mpsc;
use types::EthSpec;

/// Handles messages received from the network and client and organises syncing. This
/// functionality of this struct is to validate an decode messages from the network before
/// passing them to the internal message processor. The message processor spawns a syncing thread
/// which manages which blocks need to be requested and processed.
pub struct Router<T: BeaconChainTypes> {
    /// A channel to the network service to allow for gossip propagation.
    network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
    /// Access to the peer db for logging.
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    /// Processes validated and decoded messages from the network. Has direct access to the
    /// sync manager.
    processor: Processor<T>,
    /// The `Router` logger.
    log: slog::Logger,
}

/// Types of messages the handler can receive.
#[derive(Debug)]
pub enum RouterMessage<T: EthSpec> {
    /// We have initiated a connection to a new peer.
    PeerDialed(PeerId),
    /// Peer has disconnected,
    PeerDisconnected(PeerId),
    /// An RPC request has been received.
    RPCRequestReceived {
        peer_id: PeerId,
        id: PeerRequestId,
        request: Request,
    },
    /// An RPC response has been received.
    RPCResponseReceived {
        peer_id: PeerId,
        request_id: RequestId,
        response: Response<T>,
    },
    /// An RPC request failed
    RPCFailed {
        peer_id: PeerId,
        request_id: RequestId,
        error: RPCError,
    },
    /// A gossip message has been received. The fields are: message id, the peer that sent us this
    /// message and the message itself.
    PubsubMessage(MessageId, PeerId, PubsubMessage<T>),
    /// The peer manager has requested we re-status a peer.
    StatusPeer(PeerId),
}

impl<T: BeaconChainTypes> Router<T> {
    /// Initializes and runs the Router.
    pub fn spawn(
        beacon_chain: Arc<BeaconChain<T>>,
        network_globals: Arc<NetworkGlobals<T::EthSpec>>,
        network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
        executor: environment::TaskExecutor,
        log: slog::Logger,
    ) -> error::Result<mpsc::UnboundedSender<RouterMessage<T::EthSpec>>> {
        let message_handler_log = log.new(o!("service"=> "router"));
        trace!(message_handler_log, "Service starting");

        let (handler_send, handler_recv) = mpsc::unbounded_channel();

        // Initialise a message instance, which itself spawns the syncing thread.
        let processor = Processor::new(
            executor.clone(),
            beacon_chain,
            network_globals.clone(),
            network_send.clone(),
            &log,
        );

        // generate the Message handler
        let mut handler = Router {
            network_send,
            network_globals,
            processor,
            log: message_handler_log,
        };

        // spawn handler task and move the message handler instance into the spawned thread
        executor.spawn(
            async move {
                debug!(log, "Network message router started");
                handler_recv
                    .for_each(move |msg| future::ready(handler.handle_message(msg)))
                    .await;
            },
            "router",
        );

        Ok(handler_send)
    }

    /// Handle all messages incoming from the network service.
    fn handle_message(&mut self, message: RouterMessage<T::EthSpec>) {
        match message {
            // we have initiated a connection to a peer or the peer manager has requested a
            // re-status
            RouterMessage::PeerDialed(peer_id) | RouterMessage::StatusPeer(peer_id) => {
                self.processor.send_status(peer_id);
            }
            // A peer has disconnected
            RouterMessage::PeerDisconnected(peer_id) => {
                self.processor.on_disconnect(peer_id);
            }
            RouterMessage::RPCRequestReceived {
                peer_id,
                id,
                request,
            } => {
                self.handle_rpc_request(peer_id, id, request);
            }
            RouterMessage::RPCResponseReceived {
                peer_id,
                request_id,
                response,
            } => {
                self.handle_rpc_response(peer_id, request_id, response);
            }
            RouterMessage::RPCFailed {
                peer_id,
                request_id,
                error,
            } => {
                warn!(self.log, "RPC Error";
                    "peer_id" => peer_id.to_string(),
                    "request_id" => request_id,
                    "error" => error.to_string(),
                    "client" => self.network_globals.client(&peer_id).to_string());
                self.processor.on_rpc_error(peer_id, request_id);
            }
            RouterMessage::PubsubMessage(id, peer_id, gossip) => {
                self.handle_gossip(id, peer_id, gossip);
            }
        }
    }

    /* RPC - Related functionality */

    /// A new RPC request has been received from the network.
    fn handle_rpc_request(&mut self, peer_id: PeerId, id: PeerRequestId, request: Request) {
        match request {
            Request::Status(status_message) => {
                self.processor
                    .on_status_request(peer_id, id, status_message)
            }
            Request::BlocksByRange(request) => self
                .processor
                .on_blocks_by_range_request(peer_id, id, request),
            Request::BlocksByRoot(request) => self
                .processor
                .on_blocks_by_root_request(peer_id, id, request),
        }
    }

    /// An RPC response has been received from the network.
    // we match on id and ignore responses past the timeout.
    fn handle_rpc_response(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        response: Response<T::EthSpec>,
    ) {
        // an error could have occurred.
        match response {
            Response::Status(status_message) => {
                self.processor.on_status_response(peer_id, status_message);
            }
            Response::BlocksByRange(beacon_block) => {
                self.processor
                    .on_blocks_by_range_response(peer_id, request_id, beacon_block);
            }
            Response::BlocksByRoot(beacon_block) => {
                self.processor
                    .on_blocks_by_root_response(peer_id, request_id, beacon_block);
            }
        }
    }

    /// Handle RPC messages
    fn handle_gossip(
        &mut self,
        id: MessageId,
        peer_id: PeerId,
        gossip_message: PubsubMessage<T::EthSpec>,
    ) {
        match gossip_message {
            // Attestations should never reach the router.
            PubsubMessage::AggregateAndProofAttestation(aggregate_and_proof) => {
                if let Some(gossip_verified) = self
                    .processor
                    .verify_aggregated_attestation_for_gossip(peer_id.clone(), *aggregate_and_proof)
                {
                    self.propagate_message(id, peer_id.clone());
                    self.processor
                        .import_aggregated_attestation(peer_id, gossip_verified);
                }
            }
            PubsubMessage::Attestation(subnet_attestation) => {
                if let Some(gossip_verified) =
                    self.processor.verify_unaggregated_attestation_for_gossip(
                        peer_id.clone(),
                        subnet_attestation.1.clone(),
                        subnet_attestation.0,
                    )
                {
                    self.propagate_message(id, peer_id.clone());
                    self.processor
                        .import_unaggregated_attestation(peer_id, gossip_verified);
                }
            }
            PubsubMessage::BeaconBlock(block) => {
                match self.processor.should_forward_block(&peer_id, block) {
                    Ok(verified_block) => {
                        info!(self.log, "New block received"; "slot" => verified_block.block.slot(), "hash" => verified_block.block_root.to_string());
                        self.propagate_message(id, peer_id.clone());
                        self.processor.on_block_gossip(peer_id, verified_block);
                    }
                    Err(BlockError::ParentUnknown { .. }) => {} // performing a parent lookup
                    Err(e) => {
                        // performing a parent lookup
                        warn!(self.log, "Could not verify block for gossip";
                            "error" => format!("{:?}", e));
                    }
                }
            }
            PubsubMessage::VoluntaryExit(exit) => {
                debug!(self.log, "Received a voluntary exit"; "peer_id" => format!("{}", peer_id));
                if let Some(verified_exit) = self
                    .processor
                    .verify_voluntary_exit_for_gossip(&peer_id, *exit)
                {
                    self.propagate_message(id, peer_id.clone());
                    self.processor.import_verified_voluntary_exit(verified_exit);
                }
            }
            PubsubMessage::ProposerSlashing(proposer_slashing) => {
                debug!(
                    self.log,
                    "Received a proposer slashing";
                    "peer_id" => format!("{}", peer_id)
                );
                if let Some(verified_proposer_slashing) = self
                    .processor
                    .verify_proposer_slashing_for_gossip(&peer_id, *proposer_slashing)
                {
                    self.propagate_message(id, peer_id.clone());
                    self.processor
                        .import_verified_proposer_slashing(verified_proposer_slashing);
                }
            }
            PubsubMessage::AttesterSlashing(attester_slashing) => {
                debug!(
                    self.log,
                    "Received a attester slashing";
                    "peer_id" => format!("{}", peer_id)
                );
                if let Some(verified_attester_slashing) = self
                    .processor
                    .verify_attester_slashing_for_gossip(&peer_id, *attester_slashing)
                {
                    self.propagate_message(id, peer_id.clone());
                    self.processor
                        .import_verified_attester_slashing(verified_attester_slashing);
                }
            }
        }
    }

    /// Informs the network service that the message should be forwarded to other peers.
    fn propagate_message(&mut self, message_id: MessageId, propagation_source: PeerId) {
        self.network_send
            .send(NetworkMessage::Propagate {
                propagation_source,
                message_id,
            })
            .unwrap_or_else(|_| {
                warn!(
                    self.log,
                    "Could not send propagation request to the network service"
                )
            });
    }
}
