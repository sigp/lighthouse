//! Provides network functionality for the Syncing thread. This fundamentally wraps a network
//! channel and stores a global RPC ID to perform requests.

use super::block_sidecar_coupling::BlockBlobRequestInfo;
use super::manager::{Id, RequestId as SyncRequestId};
use super::range_sync::{BatchId, ChainId, ExpectedBatchTy};
use crate::beacon_processor::WorkEvent;
use crate::service::{NetworkMessage, RequestId};
use crate::status::ToStatusMessage;
use crate::sync::block_lookups::ForceBlockRequest;
use beacon_chain::{BeaconChain, BeaconChainTypes, EngineState};
use fnv::FnvHashMap;
use lighthouse_network::rpc::methods::BlobsByRangeRequest;
use lighthouse_network::rpc::{BlocksByRangeRequest, BlocksByRootRequest, GoodbyeReason};
use lighthouse_network::{Client, NetworkGlobals, PeerAction, PeerId, ReportSource, Request};
use slog::{debug, trace, warn};
use std::collections::hash_map::Entry;
use std::sync::Arc;
use tokio::sync::mpsc;
use types::signed_block_and_blobs::BlockWrapper;
use types::{BlobsSidecar, EthSpec, SignedBeaconBlock};

/// Wraps a Network channel to employ various RPC related network functionality for the Sync manager. This includes management of a global RPC request Id.
pub struct SyncNetworkContext<T: BeaconChainTypes> {
    /// The network channel to relay messages to the Network service.
    network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,

    /// Access to the network global vars.
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,

    /// A sequential ID for all RPC requests.
    request_id: Id,

    /// BlocksByRange requests made by the range syncing algorithm.
    range_requests: FnvHashMap<Id, (ChainId, BatchId)>,

    /// BlocksByRange requests made by backfill syncing.
    backfill_requests: FnvHashMap<Id, BatchId>,

    /// BlocksByRange requests paired with BlobsByRange requests made by the range.
    range_sidecar_pair_requests:
        FnvHashMap<Id, (ChainId, BatchId, BlockBlobRequestInfo<T::EthSpec>)>,

    /// BlocksByRange requests paired with BlobsByRange requests made by the backfill sync.
    backfill_sidecar_pair_requests: FnvHashMap<Id, (BatchId, BlockBlobRequestInfo<T::EthSpec>)>,

    /// Whether the ee is online. If it's not, we don't allow access to the
    /// `beacon_processor_send`.
    execution_engine_state: EngineState,

    /// Channel to send work to the beacon processor.
    beacon_processor_send: mpsc::Sender<WorkEvent<T>>,

    chain: Arc<BeaconChain<T>>,

    /// Logger for the `SyncNetworkContext`.
    log: slog::Logger,
}

/// Small enumeration to make dealing with block and blob requests easier.
pub enum BlockOrBlob<T: EthSpec> {
    Block(Option<Arc<SignedBeaconBlock<T>>>),
    Blob(Option<Arc<BlobsSidecar<T>>>),
}

impl<T: EthSpec> From<Option<Arc<SignedBeaconBlock<T>>>> for BlockOrBlob<T> {
    fn from(block: Option<Arc<SignedBeaconBlock<T>>>) -> Self {
        BlockOrBlob::Block(block)
    }
}

impl<T: EthSpec> From<Option<Arc<BlobsSidecar<T>>>> for BlockOrBlob<T> {
    fn from(blob: Option<Arc<BlobsSidecar<T>>>) -> Self {
        BlockOrBlob::Blob(blob)
    }
}

impl<T: BeaconChainTypes> SyncNetworkContext<T> {
    pub fn new(
        network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
        network_globals: Arc<NetworkGlobals<T::EthSpec>>,
        beacon_processor_send: mpsc::Sender<WorkEvent<T>>,
        chain: Arc<BeaconChain<T>>,
        log: slog::Logger,
    ) -> Self {
        SyncNetworkContext {
            network_send,
            network_globals,
            request_id: 1,
            range_requests: Default::default(),
            backfill_requests: Default::default(),
            range_sidecar_pair_requests: Default::default(),
            backfill_sidecar_pair_requests: Default::default(),
            execution_engine_state: EngineState::Online, // always assume `Online` at the start
            beacon_processor_send,
            chain,
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
        let status_message = chain.status_message();
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

            let request = Request::Status(status_message.clone());
            let request_id = RequestId::Router;
            let _ = self.send_network_msg(NetworkMessage::SendRequest {
                peer_id,
                request,
                request_id,
            });
        }
    }

    /// A blocks by range request for the range sync algorithm.
    pub fn blocks_by_range_request(
        &mut self,
        peer_id: PeerId,
        batch_type: ExpectedBatchTy,
        request: BlocksByRangeRequest,
        chain_id: ChainId,
        batch_id: BatchId,
    ) -> Result<Id, &'static str> {
        match batch_type {
            ExpectedBatchTy::OnlyBlock => {
                trace!(
                    self.log,
                    "Sending BlocksByRange request";
                    "method" => "BlocksByRange",
                    "count" => request.count,
                    "peer" => %peer_id,
                );
                let request = Request::BlocksByRange(request);
                let id = self.next_id();
                let request_id = RequestId::Sync(SyncRequestId::RangeSync { id });
                self.send_network_msg(NetworkMessage::SendRequest {
                    peer_id,
                    request,
                    request_id,
                })?;
                self.range_requests.insert(id, (chain_id, batch_id));
                Ok(id)
            }
            ExpectedBatchTy::OnlyBlockBlobs => {
                debug!(
                    self.log,
                    "Sending BlocksByRange and BlobsByRange requests";
                    "method" => "Mixed by range request",
                    "count" => request.count,
                    "peer" => %peer_id,
                );

                // create the shared request id. This is fine since the rpc handles substream ids.
                let id = self.next_id();
                let request_id = RequestId::Sync(SyncRequestId::RangeSidecarPair { id });

                // Create the blob request based on the blob request.
                let blobs_request = Request::BlobsByRange(BlobsByRangeRequest {
                    start_slot: request.start_slot,
                    count: request.count,
                });
                let blocks_request = Request::BlocksByRange(request);

                // Send both requests. Make sure both can be sent.
                self.send_network_msg(NetworkMessage::SendRequest {
                    peer_id,
                    request: blocks_request,
                    request_id,
                })?;
                self.send_network_msg(NetworkMessage::SendRequest {
                    peer_id,
                    request: blobs_request,
                    request_id,
                })?;
                let block_blob_info = BlockBlobRequestInfo::default();
                self.range_sidecar_pair_requests
                    .insert(id, (chain_id, batch_id, block_blob_info));
                Ok(id)
            }
        }
    }

    /// A blocks by range request sent by the backfill sync algorithm
    pub fn backfill_blocks_by_range_request(
        &mut self,
        peer_id: PeerId,
        batch_type: ExpectedBatchTy,
        request: BlocksByRangeRequest,
        batch_id: BatchId,
    ) -> Result<Id, &'static str> {
        match batch_type {
            ExpectedBatchTy::OnlyBlock => {
                trace!(
                    self.log,
                    "Sending backfill BlocksByRange request";
                    "method" => "BlocksByRange",
                    "count" => request.count,
                    "peer" => %peer_id,
                );
                let request = Request::BlocksByRange(request);
                let id = self.next_id();
                let request_id = RequestId::Sync(SyncRequestId::BackFillSync { id });
                self.send_network_msg(NetworkMessage::SendRequest {
                    peer_id,
                    request,
                    request_id,
                })?;
                self.backfill_requests.insert(id, batch_id);
                Ok(id)
            }
            ExpectedBatchTy::OnlyBlockBlobs => {
                debug!(
                    self.log,
                    "Sending backfill BlocksByRange and BlobsByRange requests";
                    "method" => "Mixed by range request",
                    "count" => request.count,
                    "peer" => %peer_id,
                );

                // create the shared request id. This is fine since the rpc handles substream ids.
                let id = self.next_id();
                let request_id = RequestId::Sync(SyncRequestId::BackFillSidecarPair { id });

                // Create the blob request based on the blob request.
                let blobs_request = Request::BlobsByRange(BlobsByRangeRequest {
                    start_slot: request.start_slot,
                    count: request.count,
                });
                let blocks_request = Request::BlocksByRange(request);

                // Send both requests. Make sure both can be sent.
                self.send_network_msg(NetworkMessage::SendRequest {
                    peer_id,
                    request: blocks_request,
                    request_id,
                })?;
                self.send_network_msg(NetworkMessage::SendRequest {
                    peer_id,
                    request: blobs_request,
                    request_id,
                })?;
                let block_blob_info = BlockBlobRequestInfo::default();
                self.backfill_sidecar_pair_requests
                    .insert(id, (batch_id, block_blob_info));
                Ok(id)
            }
        }
    }

    /// Response for a request that is only for blocks.
    pub fn range_sync_block_response(
        &mut self,
        request_id: Id,
        is_stream_terminator: bool,
    ) -> Option<(ChainId, BatchId)> {
        if is_stream_terminator {
            self.range_requests.remove(&request_id)
        } else {
            self.range_requests.get(&request_id).copied()
        }
    }

    /// Received a blocks by range response for a request that couples blocks and blobs.
    pub fn range_sync_block_and_blob_response(
        &mut self,
        request_id: Id,
        block_or_blob: BlockOrBlob<T::EthSpec>,
    ) -> Option<(
        ChainId,
        BatchId,
        Result<Vec<BlockWrapper<T::EthSpec>>, &'static str>,
    )> {
        match self.range_sidecar_pair_requests.entry(request_id) {
            Entry::Occupied(mut entry) => {
                let (_, _, info) = entry.get_mut();
                match block_or_blob {
                    BlockOrBlob::Block(maybe_block) => info.add_block_response(maybe_block),
                    BlockOrBlob::Blob(maybe_sidecar) => info.add_sidecar_response(maybe_sidecar),
                }
                if info.is_finished() {
                    // If the request is finished, dequeue everything
                    let (chain_id, batch_id, info) = entry.remove();
                    Some((chain_id, batch_id, info.into_responses()))
                } else {
                    None
                }
            }
            Entry::Vacant(_) => None,
        }
    }

    pub fn range_sync_request_failed(
        &mut self,
        request_id: Id,
        batch_type: ExpectedBatchTy,
    ) -> Option<(ChainId, BatchId)> {
        match batch_type {
            ExpectedBatchTy::OnlyBlockBlobs => self
                .range_sidecar_pair_requests
                .remove(&request_id)
                .map(|(chain_id, batch_id, _info)| (chain_id, batch_id)),
            ExpectedBatchTy::OnlyBlock => self.range_requests.remove(&request_id),
        }
    }

    pub fn backfill_request_failed(
        &mut self,
        request_id: Id,
        batch_type: ExpectedBatchTy,
    ) -> Option<BatchId> {
        match batch_type {
            ExpectedBatchTy::OnlyBlockBlobs => self
                .backfill_sidecar_pair_requests
                .remove(&request_id)
                .map(|(batch_id, _info)| batch_id),
            ExpectedBatchTy::OnlyBlock => self.backfill_requests.remove(&request_id),
        }
    }

    /// Response for a request that is only for blocks.
    pub fn backfill_sync_only_blocks_response(
        &mut self,
        request_id: Id,
        is_stream_terminator: bool,
    ) -> Option<BatchId> {
        if is_stream_terminator {
            self.backfill_requests
                .remove(&request_id)
                .map(|batch_id| batch_id)
        } else {
            self.backfill_requests.get(&request_id).copied()
        }
    }

    /// Received a blocks by range response for a request that couples blocks and blobs.
    pub fn backfill_sync_block_and_blob_response(
        &mut self,
        request_id: Id,
        block_or_blob: BlockOrBlob<T::EthSpec>,
    ) -> Option<(BatchId, Result<Vec<BlockWrapper<T::EthSpec>>, &'static str>)> {
        match self.backfill_sidecar_pair_requests.entry(request_id) {
            Entry::Occupied(mut entry) => {
                let (_, info) = entry.get_mut();
                match block_or_blob {
                    BlockOrBlob::Block(maybe_block) => info.add_block_response(maybe_block),
                    BlockOrBlob::Blob(maybe_sidecar) => info.add_sidecar_response(maybe_sidecar),
                }
                if info.is_finished() {
                    // If the request is finished, dequeue everything
                    let (batch_id, info) = entry.remove();
                    Some((batch_id, info.into_responses()))
                } else {
                    None
                }
            }
            Entry::Vacant(_) => None,
        }
    }

    /// Sends a blocks by root request for a single block lookup.
    pub fn single_block_lookup_request(
        &mut self,
        peer_id: PeerId,
        request: BlocksByRootRequest,
    ) -> Result<Id, &'static str> {
        let request = if self
            .chain
            .is_data_availability_check_required()
            .map_err(|_| "Unable to read slot clock")?
        {
            trace!(
                self.log,
                "Sending BlobsByRoot Request";
                "method" => "BlobsByRoot",
                "count" => request.block_roots.len(),
                "peer" => %peer_id
            );
            Request::BlobsByRoot(request.into())
        } else {
            trace!(
                self.log,
                "Sending BlocksByRoot Request";
                "method" => "BlocksByRoot",
                "count" => request.block_roots.len(),
                "peer" => %peer_id
            );
            Request::BlocksByRoot(request)
        };
        let id = self.next_id();
        let request_id = RequestId::Sync(SyncRequestId::SingleBlock { id });
        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request,
            request_id,
        })?;
        Ok(id)
    }

    /// Sends a blocks by root request for a parent request.
    pub fn parent_lookup_request(
        &mut self,
        peer_id: PeerId,
        request: BlocksByRootRequest,
        force_block_request: ForceBlockRequest,
    ) -> Result<Id, &'static str> {
        let request = if self
            .chain
            .is_data_availability_check_required()
            .map_err(|_| "Unable to read slot clock")?
            && matches!(force_block_request, ForceBlockRequest::False)
        {
            trace!(
                self.log,
                "Sending BlobsByRoot Request";
                "method" => "BlobsByRoot",
                "count" => request.block_roots.len(),
                "peer" => %peer_id
            );
            Request::BlobsByRoot(request.into())
        } else {
            trace!(
                self.log,
                "Sending BlocksByRoot Request";
                "method" => "BlocksByRoot",
                "count" => request.block_roots.len(),
                "peer" => %peer_id
            );
            Request::BlocksByRoot(request)
        };
        let id = self.next_id();
        let request_id = RequestId::Sync(SyncRequestId::ParentLookup { id });
        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request,
            request_id,
        })?;
        Ok(id)
    }

    pub fn is_execution_engine_online(&self) -> bool {
        self.execution_engine_state == EngineState::Online
    }

    pub fn update_execution_engine_state(&mut self, engine_state: EngineState) {
        debug!(self.log, "Sync's view on execution engine state updated";
            "past_state" => ?self.execution_engine_state, "new_state" => ?engine_state);
        self.execution_engine_state = engine_state;
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
                warn!(self.log, "Could not report peer: channel failed");
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
                warn!(self.log, "Could not report peer: channel failed"; "error"=> %e);
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
    fn send_network_msg(&mut self, msg: NetworkMessage<T::EthSpec>) -> Result<(), &'static str> {
        self.network_send.send(msg).map_err(|_| {
            debug!(self.log, "Could not send message to the network service");
            "Network channel send Failed"
        })
    }

    pub fn processor_channel_if_enabled(&self) -> Option<&mpsc::Sender<WorkEvent<T>>> {
        self.is_execution_engine_online()
            .then_some(&self.beacon_processor_send)
    }

    pub fn processor_channel(&self) -> &mpsc::Sender<WorkEvent<T>> {
        &self.beacon_processor_send
    }

    fn next_id(&mut self) -> Id {
        let id = self.request_id;
        self.request_id += 1;
        id
    }

    pub fn batch_type(&self, epoch: types::Epoch) -> ExpectedBatchTy {
        // Keep tests only for blocks.
        #[cfg(test)]
        {
            return ExpectedBatchTy::OnlyBlock;
        }
        #[cfg(not(test))]
        {
            use super::range_sync::EPOCHS_PER_BATCH;
            assert_eq!(
                EPOCHS_PER_BATCH, 1,
                "If this is not one, everything will fail horribly"
            );

            // Here we need access to the beacon chain, check the fork boundary, the current epoch, the
            // blob period to serve and check with that if the batch is a blob batch or not.
            // NOTE: This would carelessly assume batch sizes are always 1 epoch, to avoid needing to
            // align with the batch boundary.

            if let Some(data_availability_boundary) = self.chain.data_availability_boundary() {
                if epoch >= data_availability_boundary {
                    ExpectedBatchTy::OnlyBlockBlobs
                } else {
                    ExpectedBatchTy::OnlyBlock
                }
            } else {
                ExpectedBatchTy::OnlyBlock
            }
        }
    }
}
