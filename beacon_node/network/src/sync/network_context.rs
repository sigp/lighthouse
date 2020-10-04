//! Provides network functionality for the Syncing thread. This fundamentally wraps a network
//! channel and stores a global RPC ID to perform requests.

use super::range_sync::{BatchId, ChainId};
use super::RequestId as SyncRequestId;
use crate::router::processor::status_message;
use crate::service::NetworkMessage;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::rpc::{BlocksByRangeRequest, BlocksByRootRequest, GoodbyeReason, RequestId};
use eth2_libp2p::{Client, NetworkGlobals, PeerAction, PeerId, Request};
use fnv::FnvHashMap;
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
    request_id: SyncRequestId,

    /// BlocksByRange requests made by range syncing chains.
    range_requests: FnvHashMap<SyncRequestId, (ChainId, BatchId)>,

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
            range_requests: FnvHashMap::default(),
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

    pub fn status_peers<U: BeaconChainTypes>(
        &mut self,
        chain: Arc<BeaconChain<U>>,
        peers: impl Iterator<Item = PeerId>,
    ) {
        if let Some(status_message) = status_message(&chain) {
            for peer_id in peers {
                debug!(
                    self.log,
                    "Sending Status Request";
                    "peer" => %peer_id,
                    "fork_digest" => ?status_message.fork_digest,
                    "finalized_root" => ?status_message.finalized_root,
                    "finalized_epoch" => ?status_message.finalized_epoch,
                    "head_root" => %status_message.head_root,
                    "head_slot" => %status_message.head_slot,
                );

                let _ = self.send_rpc_request(peer_id, Request::Status(status_message.clone()));
            }
        }
    }

    pub fn blocks_by_range_request(
        &mut self,
        peer_id: PeerId,
        request: BlocksByRangeRequest,
        chain_id: ChainId,
        batch_id: BatchId,
    ) -> Result<(), &'static str> {
        trace!(
            self.log,
            "Sending BlocksByRange Request";
            "method" => "BlocksByRange",
            "count" => request.count,
            "peer" => %peer_id,
        );
        let req_id = self.send_rpc_request(peer_id, Request::BlocksByRange(request))?;
        self.range_requests.insert(req_id, (chain_id, batch_id));
        Ok(())
    }

    pub fn blocks_by_range_response(
        &mut self,
        request_id: usize,
        remove: bool,
    ) -> Option<(ChainId, BatchId)> {
        // NOTE: we can't guarantee that the request must be registered as it could receive more
        // than an error, and be removed after receiving the first one.
        // FIXME: https://github.com/sigp/lighthouse/issues/1634
        if remove {
            self.range_requests.remove(&request_id)
        } else {
            self.range_requests.get(&request_id).cloned()
        }
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
