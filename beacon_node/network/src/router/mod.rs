//! This module handles incoming network messages.
//!
//! It routes the messages to appropriate services.
//! It handles requests at the application layer in its associated processor and directs
//! syncing-related responses to the Sync manager.
#![allow(clippy::unit_arg)]

mod processor;

use crate::error;
use crate::service::NetworkMessage;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::{
    rpc::RequestId, MessageId, NetworkGlobals, PeerId, PeerRequestId, PubsubMessage, Request,
    Response,
};
use futures::prelude::*;
use processor::Processor;
use slog::{debug, o, trace};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;
use types::EthSpec;

/// Handles messages received from the network and client and organises syncing. This
/// functionality of this struct is to validate an decode messages from the network before
/// passing them to the internal message processor. The message processor spawns a syncing thread
/// which manages which blocks need to be requested and processed.
pub struct Router<T: BeaconChainTypes> {
    /// Access to the peer db.
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
    },
    /// A gossip message has been received. The fields are: message id, the peer that sent us this
    /// message, the message itself and a bool which indicates if the message should be processed
    /// by the beacon chain after successful verification.
    PubsubMessage(MessageId, PeerId, PubsubMessage<T>, bool),
    /// The peer manager has requested we re-status a peer.
    StatusPeer(PeerId),
}

impl<T: BeaconChainTypes> Router<T> {
    /// Initializes and runs the Router.
    pub fn spawn(
        beacon_chain: Arc<BeaconChain<T>>,
        network_globals: Arc<NetworkGlobals<T::EthSpec>>,
        network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
        executor: task_executor::TaskExecutor,
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
            network_send,
            &log,
        );

        // generate the Message handler
        let mut handler = Router {
            network_globals,
            processor,
            log: message_handler_log,
        };

        // spawn handler task and move the message handler instance into the spawned thread
        executor.spawn(
            async move {
                debug!(log, "Network message router started");
                UnboundedReceiverStream::new(handler_recv)
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
            } => {
                self.processor.on_rpc_error(peer_id, request_id);
            }
            RouterMessage::PubsubMessage(id, peer_id, gossip, should_process) => {
                self.handle_gossip(id, peer_id, gossip, should_process);
            }
        }
    }

    /* RPC - Related functionality */

    /// A new RPC request has been received from the network.
    fn handle_rpc_request(&mut self, peer_id: PeerId, id: PeerRequestId, request: Request) {
        if !self.network_globals.peers.read().is_connected(&peer_id) {
            debug!(self.log, "Dropping request of disconnected peer"; "peer_id" => %peer_id, "request" => ?request);
            return;
        }
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

    /// Handle RPC messages.
    /// Note: `should_process` is currently only useful for the `Attestation` variant.
    /// if `should_process` is `false`, we only propagate the message on successful verification,
    /// else, we propagate **and** import into the beacon chain.
    fn handle_gossip(
        &mut self,
        id: MessageId,
        peer_id: PeerId,
        gossip_message: PubsubMessage<T::EthSpec>,
        should_process: bool,
    ) {
        match gossip_message {
            // Attestations should never reach the router.
            PubsubMessage::AggregateAndProofAttestation(aggregate_and_proof) => {
                self.processor
                    .on_aggregated_attestation_gossip(id, peer_id, *aggregate_and_proof);
            }
            PubsubMessage::Attestation(subnet_attestation) => {
                self.processor.on_unaggregated_attestation_gossip(
                    id,
                    peer_id,
                    subnet_attestation.1.clone(),
                    subnet_attestation.0,
                    should_process,
                );
            }
            PubsubMessage::BeaconBlock(block) => {
                self.processor.on_block_gossip(
                    id,
                    peer_id,
                    self.network_globals.client(&peer_id),
                    block,
                );
            }
            PubsubMessage::VoluntaryExit(exit) => {
                debug!(self.log, "Received a voluntary exit"; "peer_id" => %peer_id);
                self.processor.on_voluntary_exit_gossip(id, peer_id, exit);
            }
            PubsubMessage::ProposerSlashing(proposer_slashing) => {
                debug!(
                    self.log,
                    "Received a proposer slashing";
                    "peer_id" => %peer_id
                );
                self.processor
                    .on_proposer_slashing_gossip(id, peer_id, proposer_slashing);
            }
            PubsubMessage::AttesterSlashing(attester_slashing) => {
                debug!(
                    self.log,
                    "Received a attester slashing";
                    "peer_id" => %peer_id
                );
                self.processor
                    .on_attester_slashing_gossip(id, peer_id, attester_slashing);
            }
            PubsubMessage::SignedContributionAndProof(contribution_and_proof) => {
                trace!(
                    self.log,
                    "Received sync committee aggregate";
                    "peer_id" => %peer_id
                );
                self.processor.on_sync_committee_contribution_gossip(
                    id,
                    peer_id,
                    *contribution_and_proof,
                );
            }
            PubsubMessage::SyncCommitteeMessage(sync_committtee_msg) => {
                trace!(
                    self.log,
                    "Received sync committee signature";
                    "peer_id" => %peer_id
                );
                self.processor.on_sync_committee_signature_gossip(
                    id,
                    peer_id,
                    sync_committtee_msg.1,
                    sync_committtee_msg.0,
                );
            }
        }
    }
}
