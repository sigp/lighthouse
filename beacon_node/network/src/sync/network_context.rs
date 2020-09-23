//! Provides network functionality for the Syncing thread. This fundamentally wraps a network
//! channel and stores a global RPC ID to perform requests.

use crate::router::processor::status_message;
use crate::service::NetworkMessage;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::rpc::{BlocksByRangeRequest, BlocksByRootRequest, GoodbyeReason, RequestId};
use eth2_libp2p::{Client, NetworkGlobals, PeerAction, PeerId, Request};
use slog::{debug, trace, warn};
use std::sync::Arc;
use tokio::sync::mpsc;
use types::EthSpec;

/// Wraps a Network channel to employ various RPC related network functionality for the Sync manager. This includes management of a global RPC request Id.

pub struct SyncNetworkContext<T: EthSpec> {
    /// The network channel to relay messages to the Network service.
    network_send: mpsc::UnboundedSender<NetworkMessage<T>>,

    /// Access to the network global vars.
    network_globals: Arc<NetworkGlobals<T>>,

    /// A sequential ID for all RPC requests.
    request_id: usize,
    /// Logger for the `SyncNetworkContext`.
    log: slog::Logger,
}

impl<T: EthSpec> SyncNetworkContext<T> {
    pub fn new(
        network_send: mpsc::UnboundedSender<NetworkMessage<T>>,
        network_globals: Arc<NetworkGlobals<T>>,
        log: slog::Logger,
    ) -> Self {
        Self {
            network_send,
            network_globals,
            request_id: 1,
            log,
        }
    }

    /// Returns the Client type of the peer if known
    pub fn client_type(&self, peer_id: &PeerId) -> Client {
        self.network_globals
            .peers
            .read()
            .peer_info(peer_id)
            .map(|info| info.client.clone())
            .unwrap_or_default()
    }

    pub fn status_peer<U: BeaconChainTypes>(
        &mut self,
        chain: Arc<BeaconChain<U>>,
        peer_id: PeerId,
    ) {
        if let Some(status_message) = status_message(&chain) {
            debug!(
                self.log,
                "Sending Status Request";
                "peer" => format!("{:?}", peer_id),
                "fork_digest" => format!("{:?}", status_message.fork_digest),
                "finalized_root" => format!("{:?}", status_message.finalized_root),
                "finalized_epoch" => format!("{:?}", status_message.finalized_epoch),
                "head_root" => format!("{}", status_message.head_root),
                "head_slot" => format!("{}", status_message.head_slot),
            );

            let _ = self.send_rpc_request(peer_id, Request::Status(status_message));
        }
    }

    pub fn blocks_by_range_request(
        &mut self,
        peer_id: PeerId,
        request: BlocksByRangeRequest,
    ) -> Result<usize, &'static str> {
        trace!(
            self.log,
            "Sending BlocksByRange Request";
            "method" => "BlocksByRange",
            "count" => request.count,
            "peer" => format!("{:?}", peer_id)
        );
        self.send_rpc_request(peer_id, Request::BlocksByRange(request))
    }

    pub fn blocks_by_root_request(
        &mut self,
        peer_id: PeerId,
        request: BlocksByRootRequest,
    ) -> Result<usize, &'static str> {
        trace!(
            self.log,
            "Sending BlocksByRoot Request";
            "method" => "BlocksByRoot",
            "count" => request.block_roots.len(),
            "peer" => format!("{:?}", peer_id)
        );
        self.send_rpc_request(peer_id, Request::BlocksByRoot(request))
    }

    pub fn goodbye_peer(&mut self, peer_id: PeerId, reason: GoodbyeReason) {
        self.network_send
            .send(NetworkMessage::GoodbyePeer { peer_id, reason })
            .unwrap_or_else(|_| {
                warn!(self.log, "Could not report peer, channel failed");
            });
    }

    pub fn report_peer(&mut self, peer_id: PeerId, action: PeerAction) {
        debug!(self.log, "Sync reporting peer"; "peer_id" => peer_id.to_string(), "action" => action.to_string());
        self.network_send
            .send(NetworkMessage::ReportPeer { peer_id, action })
            .unwrap_or_else(|e| {
                warn!(self.log, "Could not report peer, channel failed"; "error"=> e.to_string());
            });
    }

    pub fn send_rpc_request(
        &mut self,
        peer_id: PeerId,
        request: Request,
    ) -> Result<usize, &'static str> {
        let request_id = self.request_id;
        self.request_id += 1;
        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request_id: RequestId::Sync(request_id),
            request,
        })?;
        Ok(request_id)
    }

    pub fn subscribe_core_topics(&mut self) {
        self.network_send
            .send(NetworkMessage::SubscribeCoreTopics)
            .unwrap_or_else(|e| {
                warn!(self.log, "Could not subscribe to core topics."; "error" => e.to_string());
            });
    }

    fn send_network_msg(&mut self, msg: NetworkMessage<T>) -> Result<(), &'static str> {
        self.network_send.send(msg).map_err(|_| {
            debug!(self.log, "Could not send message to the network service");
            "Network channel send Failed"
        })
    }
}
