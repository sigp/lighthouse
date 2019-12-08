//! Provides network functionality for the Syncing thread. This fundamentally wraps a network
//! channel and stores a global RPC ID to perform requests.

use super::message_processor::status_message;
use crate::service::NetworkMessage;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::rpc::methods::*;
use eth2_libp2p::rpc::{RPCEvent, RPCRequest, RequestId};
use eth2_libp2p::PeerId;
use slog::{debug, trace, warn};
use std::sync::Weak;
use tokio::sync::mpsc;

/// Wraps a Network channel to employ various RPC related network functionality for the Sync manager. This includes management of a global RPC request Id.

pub struct SyncNetworkContext {
    /// The network channel to relay messages to the Network service.
    network_send: mpsc::UnboundedSender<NetworkMessage>,

    request_id: RequestId,
    /// Logger for the `SyncNetworkContext`.
    log: slog::Logger,
}

impl SyncNetworkContext {
    pub fn new(network_send: mpsc::UnboundedSender<NetworkMessage>, log: slog::Logger) -> Self {
        Self {
            network_send,
            request_id: 0,
            log,
        }
    }

    pub fn status_peer<T: BeaconChainTypes>(
        &mut self,
        chain: Weak<BeaconChain<T>>,
        peer_id: PeerId,
    ) {
        trace!(
            self.log,
            "Sending Status Request";
            "method" => "STATUS",
            "peer" => format!("{:?}", peer_id)
        );
        if let Some(chain) = chain.upgrade() {
            let _ = self.send_rpc_request(peer_id, RPCRequest::Status(status_message(&chain)));
        }
    }

    pub fn blocks_by_range_request(
        &mut self,
        peer_id: PeerId,
        request: BlocksByRangeRequest,
    ) -> Result<RequestId, &'static str> {
        trace!(
            self.log,
            "Sending BlocksByRange Request";
            "method" => "BlocksByRange",
            "count" => request.count,
            "peer" => format!("{:?}", peer_id)
        );
        self.send_rpc_request(peer_id.clone(), RPCRequest::BlocksByRange(request))
    }

    pub fn blocks_by_root_request(
        &mut self,
        peer_id: PeerId,
        request: BlocksByRootRequest,
    ) -> Result<RequestId, &'static str> {
        trace!(
            self.log,
            "Sending BlocksByRoot Request";
            "method" => "BlocksByRoot",
            "count" => request.block_roots.len(),
            "peer" => format!("{:?}", peer_id)
        );
        self.send_rpc_request(peer_id.clone(), RPCRequest::BlocksByRoot(request))
    }

    pub fn downvote_peer(&mut self, peer_id: PeerId) {
        debug!(
            self.log,
            "Peer downvoted";
            "peer" => format!("{:?}", peer_id)
        );
        // TODO: Implement reputation
        self.disconnect(peer_id.clone(), GoodbyeReason::Fault);
    }

    fn disconnect(&mut self, peer_id: PeerId, reason: GoodbyeReason) {
        warn!(
            &self.log,
            "Disconnecting peer (RPC)";
            "reason" => format!("{:?}", reason),
            "peer_id" => format!("{:?}", peer_id),
        );

        // ignore the error if the channel send fails
        let _ = self.send_rpc_request(peer_id.clone(), RPCRequest::Goodbye(reason));
        self.network_send
            .try_send(NetworkMessage::Disconnect { peer_id })
            .unwrap_or_else(|_| {
                warn!(
                    self.log,
                    "Could not send a Disconnect to the network service"
                )
            });
    }

    pub fn send_rpc_request(
        &mut self,
        peer_id: PeerId,
        rpc_request: RPCRequest,
    ) -> Result<RequestId, &'static str> {
        let request_id = self.request_id;
        self.request_id += 1;
        self.send_rpc_event(peer_id, RPCEvent::Request(request_id, rpc_request))?;
        Ok(request_id)
    }

    fn send_rpc_event(&mut self, peer_id: PeerId, rpc_event: RPCEvent) -> Result<(), &'static str> {
        self.network_send
            .try_send(NetworkMessage::RPC(peer_id, rpc_event))
            .map_err(|_| {
                // This is likely to happen when shutting down. Suppress this warning to trace for now
                trace!(
                    self.log,
                    "Could not send RPC message to the network service"
                );
                "Network channel send Failed"
            })
    }
}
