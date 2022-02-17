//! Provides network functionality for the Syncing thread. This fundamentally wraps a network
//! channel and stores a global RPC ID to perform requests.

use super::manager::{Id, RequestId as SyncRequestId};
use super::range_sync::{BatchId, ChainId};
use crate::service::{NetworkMessage, RequestId};
use crate::status::ToStatusMessage;
use lighthouse_network::rpc::{BlocksByRangeRequest, BlocksByRootRequest, GoodbyeReason};
use lighthouse_network::{Client, NetworkGlobals, PeerAction, PeerId, ReportSource, Request};
use slog::{debug, trace, warn};
use std::sync::Arc;
use tokio::sync::mpsc;
use types::{EthSpec, Hash256};

/// Wraps a Network channel to employ various RPC related network functionality for the Sync manager. This includes management of a global RPC request Id.

pub struct SyncNetworkContext<T: EthSpec> {
    /// The network channel to relay messages to the Network service.
    network_send: mpsc::UnboundedSender<NetworkMessage<T>>,

    /// Access to the network global vars.
    network_globals: Arc<NetworkGlobals<T>>,

    /// A sequential ID for all RPC requests.
    identifier: Id,

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
            identifier: 1,
            log,
        }
    }

    /// Returns the Client type of the peer if known
    pub fn client_type(&self, peer_id: &PeerId) -> Client {
        self.network_globals
            .peers
            .read()
            .peer_info(peer_id)
            .map(|info| info.client().clone())
            .unwrap_or_default()
    }

    pub fn status_peers<C: ToStatusMessage>(
        &mut self,
        chain: &C,
        peers: impl Iterator<Item = PeerId>,
    ) {
        if let Ok(status_message) = chain.status_message() {
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

                let _ = self.send_network_msg(NetworkMessage::SendRequest {
                    peer_id,
                    request: Request::Status(status_message.clone()),
                    request_id: RequestId::Router, // router will send the response to the processor
                });
            }
        }
    }

    /// A blocks by range request for the range sync algorithm.
    pub fn blocks_by_range_request(
        &mut self,
        peer_id: PeerId,
        request: BlocksByRangeRequest,
        chain_id: ChainId,
        batch_id: BatchId,
    ) -> Result<Id, &'static str> {
        trace!(
            self.log,
            "Sending BlocksByRange Request";
            "method" => "BlocksByRange",
            "count" => request.count,
            "peer" => %peer_id,
        );

        let identifier = self.next_id();
        let request_id = SyncRequestId::RangeSync {
            id: identifier,
            epoch: batch_id,
            chain: chain_id,
        };

        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request_id: RequestId::Sync(request_id),
            request: Request::BlocksByRange(request),
        })?;
        Ok(identifier)
    }

    /// A blocks by range request sent by the backfill sync algorithm
    pub fn backfill_blocks_by_range_request(
        &mut self,
        peer_id: PeerId,
        request: BlocksByRangeRequest,
        batch_id: BatchId,
    ) -> Result<Id, &'static str> {
        trace!(
            self.log,
            "Sending backfill BlocksByRange Request";
            "method" => "BlocksByRange",
            "count" => request.count,
            "peer" => %peer_id,
        );
        let identifier = self.next_id();
        let request_id = SyncRequestId::BackFillSync {
            id: identifier,
            epoch: batch_id,
        };

        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request_id: RequestId::Sync(request_id),
            request: Request::BlocksByRange(request),
        })?;
        Ok(identifier)
    }

    /// Sends a blocks by root request.
    pub fn blocks_by_root_request(
        &mut self,
        peer_id: PeerId,
        request: BlocksByRootRequest,
    ) -> Result<Id, &'static str> {
        trace!(
            self.log,
            "Sending BlocksByRoot Request for single block lookup";
            "method" => "BlocksByRoot",
            "count" => request.block_roots.len(),
            "peer" => %peer_id
        );
        let identifier = self.next_id();
        let request_id = SyncRequestId::SingleBlock { id: identifier };

        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request_id: RequestId::Sync(request_id),
            request: Request::BlocksByRoot(request),
        })?;
        Ok(identifier)
    }

    /// Sends a blocks by root request for a parent lookup.
    pub fn blocks_by_root_parent_request(
        &mut self,
        peer_id: PeerId,
        chain_id: Hash256,
        request: BlocksByRootRequest,
    ) -> Result<Id, &'static str> {
        trace!(
            self.log,
            "Sending BlocksByRoot Request for single block lookup";
            "method" => "BlocksByRoot",
            "count" => request.block_roots.len(),
            "peer" => %peer_id
        );
        let identifier = self.next_id();
        let request_id = SyncRequestId::ParentLookup {
            id: identifier,
            chain: chain_id,
        };

        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request_id: RequestId::Sync(request_id),
            request: Request::BlocksByRoot(request),
        })?;
        Ok(identifier)
    }

    /// Terminates the connection with the peer and bans them.
    pub fn goodbye_peer(&mut self, peer_id: PeerId, reason: GoodbyeReason) {
        self.network_send
            .send(NetworkMessage::GoodbyePeer {
                peer_id,
                reason,
                source: ReportSource::SyncService,
            })
            .unwrap_or_else(|_| {
                warn!(self.log, "Could not report peer, channel failed");
            });
    }

    /// Reports to the scoring algorithm the behaviour of a peer.
    pub fn report_peer(&mut self, peer_id: PeerId, action: PeerAction, msg: &'static str) {
        debug!(self.log, "Sync reporting peer"; "peer_id" => %peer_id, "action" => %action);
        self.network_send
            .send(NetworkMessage::ReportPeer {
                peer_id,
                action,
                source: ReportSource::SyncService,
                msg,
            })
            .unwrap_or_else(|e| {
                warn!(self.log, "Could not report peer, channel failed"; "error"=> %e);
            });
    }

    /// Subscribes to core topics.
    pub fn subscribe_core_topics(&mut self) {
        self.network_send
            .send(NetworkMessage::SubscribeCoreTopics)
            .unwrap_or_else(|e| {
                warn!(self.log, "Could not subscribe to core topics."; "error" => %e);
            });
    }

    /// Sends an arbitrary network message.
    fn send_network_msg(&mut self, msg: NetworkMessage<T>) -> Result<(), &'static str> {
        self.network_send.send(msg).map_err(|_| {
            debug!(self.log, "Could not send message to the network service");
            "Network channel send Failed"
        })
    }

    fn next_id(&mut self) -> Id {
        let id = self.identifier;
        self.identifier += 1;
        id
    }
}
