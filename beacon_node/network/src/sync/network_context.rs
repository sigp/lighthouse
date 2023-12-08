//! Provides network functionality for the Syncing thread. This fundamentally wraps a network
//! channel and stores a global RPC ID to perform requests.

use super::block_sidecar_coupling::BlocksAndBlobsRequestInfo;
use super::manager::{Id, RequestId as SyncRequestId};
use super::range_sync::{BatchId, ByRangeRequestType, ChainId};
use crate::network_beacon_processor::NetworkBeaconProcessor;
use crate::service::{NetworkMessage, RequestId};
use crate::status::ToStatusMessage;
use crate::sync::block_lookups::common::LookupType;
use crate::sync::manager::SingleLookupReqId;
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::{BeaconChain, BeaconChainTypes, EngineState};
use fnv::FnvHashMap;
use lighthouse_network::rpc::methods::{BlobsByRangeRequest, BlobsByRootRequest};
use lighthouse_network::rpc::{BlocksByRangeRequest, BlocksByRootRequest, GoodbyeReason};
use lighthouse_network::{Client, NetworkGlobals, PeerAction, PeerId, ReportSource, Request};
use slog::{debug, trace, warn};
use std::collections::hash_map::Entry;
use std::sync::Arc;
use tokio::sync::mpsc;
use types::{BlobSidecar, EthSpec, SignedBeaconBlock};

pub struct BlocksAndBlobsByRangeResponse<T: EthSpec> {
    pub batch_id: BatchId,
    pub responses: Result<Vec<RpcBlock<T>>, String>,
}

pub struct BlocksAndBlobsByRangeRequest<T: EthSpec> {
    pub chain_id: ChainId,
    pub batch_id: BatchId,
    pub block_blob_info: BlocksAndBlobsRequestInfo<T>,
}

/// Wraps a Network channel to employ various RPC related network functionality for the Sync manager. This includes management of a global RPC request Id.
pub struct SyncNetworkContext<T: BeaconChainTypes> {
    /// The network channel to relay messages to the Network service.
    network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,

    /// A sequential ID for all RPC requests.
    request_id: Id,

    /// BlocksByRange requests made by the range syncing algorithm.
    range_requests: FnvHashMap<Id, (ChainId, BatchId)>,

    /// BlocksByRange requests made by backfill syncing.
    backfill_requests: FnvHashMap<Id, BatchId>,

    /// BlocksByRange requests paired with BlobsByRange requests made by the range.
    range_blocks_and_blobs_requests: FnvHashMap<Id, BlocksAndBlobsByRangeRequest<T::EthSpec>>,

    /// BlocksByRange requests paired with BlobsByRange requests made by the backfill sync.
    backfill_blocks_and_blobs_requests:
        FnvHashMap<Id, (BatchId, BlocksAndBlobsRequestInfo<T::EthSpec>)>,

    /// Whether the ee is online. If it's not, we don't allow access to the
    /// `beacon_processor_send`.
    execution_engine_state: EngineState,

    /// Sends work to the beacon processor via a channel.
    network_beacon_processor: Arc<NetworkBeaconProcessor<T>>,

    pub chain: Arc<BeaconChain<T>>,

    /// Logger for the `SyncNetworkContext`.
    pub log: slog::Logger,
}

/// Small enumeration to make dealing with block and blob requests easier.
pub enum BlockOrBlob<T: EthSpec> {
    Block(Option<Arc<SignedBeaconBlock<T>>>),
    Blob(Option<Arc<BlobSidecar<T>>>),
}

impl<T: EthSpec> From<Option<Arc<SignedBeaconBlock<T>>>> for BlockOrBlob<T> {
    fn from(block: Option<Arc<SignedBeaconBlock<T>>>) -> Self {
        BlockOrBlob::Block(block)
    }
}

impl<T: EthSpec> From<Option<Arc<BlobSidecar<T>>>> for BlockOrBlob<T> {
    fn from(blob: Option<Arc<BlobSidecar<T>>>) -> Self {
        BlockOrBlob::Blob(blob)
    }
}

impl<T: BeaconChainTypes> SyncNetworkContext<T> {
    pub fn new(
        network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
        network_beacon_processor: Arc<NetworkBeaconProcessor<T>>,
        chain: Arc<BeaconChain<T>>,
        log: slog::Logger,
    ) -> Self {
        SyncNetworkContext {
            network_send,
            execution_engine_state: EngineState::Online, // always assume `Online` at the start
            request_id: 1,
            range_requests: FnvHashMap::default(),
            backfill_requests: FnvHashMap::default(),
            range_blocks_and_blobs_requests: FnvHashMap::default(),
            backfill_blocks_and_blobs_requests: FnvHashMap::default(),
            network_beacon_processor,
            chain,
            log,
        }
    }

    pub fn network_globals(&self) -> &NetworkGlobals<T::EthSpec> {
        &self.network_beacon_processor.network_globals
    }

    /// Returns the Client type of the peer if known
    pub fn client_type(&self, peer_id: &PeerId) -> Client {
        self.network_globals()
            .peers
            .read()
            .peer_info(peer_id)
            .map(|info| info.client().clone())
            .unwrap_or_default()
    }

    pub fn status_peers<C: ToStatusMessage>(&self, chain: &C, peers: impl Iterator<Item = PeerId>) {
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
        batch_type: ByRangeRequestType,
        request: BlocksByRangeRequest,
        chain_id: ChainId,
        batch_id: BatchId,
    ) -> Result<Id, &'static str> {
        match batch_type {
            ByRangeRequestType::Blocks => {
                trace!(
                    self.log,
                    "Sending BlocksByRange request";
                    "method" => "BlocksByRange",
                    "count" => request.count(),
                    "peer" => %peer_id,
                );
                let request = Request::BlocksByRange(request);
                let id = self.next_id();
                let request_id = RequestId::Sync(SyncRequestId::RangeBlocks { id });
                self.send_network_msg(NetworkMessage::SendRequest {
                    peer_id,
                    request,
                    request_id,
                })?;
                self.range_requests.insert(id, (chain_id, batch_id));
                Ok(id)
            }
            ByRangeRequestType::BlocksAndBlobs => {
                debug!(
                    self.log,
                    "Sending BlocksByRange and BlobsByRange requests";
                    "method" => "Mixed by range request",
                    "count" => request.count(),
                    "peer" => %peer_id,
                );

                // create the shared request id. This is fine since the rpc handles substream ids.
                let id = self.next_id();
                let request_id = RequestId::Sync(SyncRequestId::RangeBlockAndBlobs { id });

                // Create the blob request based on the blob request.
                let blobs_request = Request::BlobsByRange(BlobsByRangeRequest {
                    start_slot: *request.start_slot(),
                    count: *request.count(),
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
                let block_blob_info = BlocksAndBlobsRequestInfo::default();
                self.range_blocks_and_blobs_requests.insert(
                    id,
                    BlocksAndBlobsByRangeRequest {
                        chain_id,
                        batch_id,
                        block_blob_info,
                    },
                );
                Ok(id)
            }
        }
    }

    /// A blocks by range request sent by the backfill sync algorithm
    pub fn backfill_blocks_by_range_request(
        &mut self,
        peer_id: PeerId,
        batch_type: ByRangeRequestType,
        request: BlocksByRangeRequest,
        batch_id: BatchId,
    ) -> Result<Id, &'static str> {
        match batch_type {
            ByRangeRequestType::Blocks => {
                trace!(
                    self.log,
                    "Sending backfill BlocksByRange request";
                    "method" => "BlocksByRange",
                    "count" => request.count(),
                    "peer" => %peer_id,
                );
                let request = Request::BlocksByRange(request);
                let id = self.next_id();
                let request_id = RequestId::Sync(SyncRequestId::BackFillBlocks { id });
                self.send_network_msg(NetworkMessage::SendRequest {
                    peer_id,
                    request,
                    request_id,
                })?;
                self.backfill_requests.insert(id, batch_id);
                Ok(id)
            }
            ByRangeRequestType::BlocksAndBlobs => {
                debug!(
                    self.log,
                    "Sending backfill BlocksByRange and BlobsByRange requests";
                    "method" => "Mixed by range request",
                    "count" => request.count(),
                    "peer" => %peer_id,
                );

                // create the shared request id. This is fine since the rpc handles substream ids.
                let id = self.next_id();
                let request_id = RequestId::Sync(SyncRequestId::BackFillBlockAndBlobs { id });

                // Create the blob request based on the blob request.
                let blobs_request = Request::BlobsByRange(BlobsByRangeRequest {
                    start_slot: *request.start_slot(),
                    count: *request.count(),
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
                let block_blob_info = BlocksAndBlobsRequestInfo::default();
                self.backfill_blocks_and_blobs_requests
                    .insert(id, (batch_id, block_blob_info));
                Ok(id)
            }
        }
    }

    /// Response for a request that is only for blocks.
    pub fn range_sync_block_only_response(
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
    ) -> Option<(ChainId, BlocksAndBlobsByRangeResponse<T::EthSpec>)> {
        match self.range_blocks_and_blobs_requests.entry(request_id) {
            Entry::Occupied(mut entry) => {
                let req = entry.get_mut();
                let info = &mut req.block_blob_info;
                match block_or_blob {
                    BlockOrBlob::Block(maybe_block) => info.add_block_response(maybe_block),
                    BlockOrBlob::Blob(maybe_sidecar) => info.add_sidecar_response(maybe_sidecar),
                }
                if info.is_finished() {
                    // If the request is finished, dequeue everything
                    let BlocksAndBlobsByRangeRequest {
                        chain_id,
                        batch_id,
                        block_blob_info,
                    } = entry.remove();
                    Some((
                        chain_id,
                        BlocksAndBlobsByRangeResponse {
                            batch_id,
                            responses: block_blob_info.into_responses(),
                        },
                    ))
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
        batch_type: ByRangeRequestType,
    ) -> Option<(ChainId, BatchId)> {
        let req = match batch_type {
            ByRangeRequestType::BlocksAndBlobs => self
                .range_blocks_and_blobs_requests
                .remove(&request_id)
                .map(|req| (req.chain_id, req.batch_id)),
            ByRangeRequestType::Blocks => self.range_requests.remove(&request_id),
        };
        if let Some(req) = req {
            debug!(
                self.log,
                "Range sync request failed";
                "request_id" => request_id,
                "batch_type" => ?batch_type,
                "chain_id" => ?req.0,
                "batch_id" => ?req.1
            );
            Some(req)
        } else {
            debug!(self.log, "Range sync request failed"; "request_id" => request_id, "batch_type" => ?batch_type);
            None
        }
    }

    pub fn backfill_request_failed(
        &mut self,
        request_id: Id,
        batch_type: ByRangeRequestType,
    ) -> Option<BatchId> {
        let batch_id = match batch_type {
            ByRangeRequestType::BlocksAndBlobs => self
                .backfill_blocks_and_blobs_requests
                .remove(&request_id)
                .map(|(batch_id, _info)| batch_id),
            ByRangeRequestType::Blocks => self.backfill_requests.remove(&request_id),
        };
        if let Some(batch_id) = batch_id {
            debug!(
                self.log,
                "Backfill sync request failed";
                "request_id" => request_id,
                "batch_type" => ?batch_type,
                "batch_id" => ?batch_id
            );
            Some(batch_id)
        } else {
            debug!(self.log, "Backfill sync request failed"; "request_id" => request_id, "batch_type" => ?batch_type);
            None
        }
    }

    /// Response for a request that is only for blocks.
    pub fn backfill_sync_only_blocks_response(
        &mut self,
        request_id: Id,
        is_stream_terminator: bool,
    ) -> Option<BatchId> {
        if is_stream_terminator {
            self.backfill_requests.remove(&request_id)
        } else {
            self.backfill_requests.get(&request_id).copied()
        }
    }

    /// Received a blocks by range or blobs by range response for a request that couples blocks '
    /// and blobs.
    pub fn backfill_sync_block_and_blob_response(
        &mut self,
        request_id: Id,
        block_or_blob: BlockOrBlob<T::EthSpec>,
    ) -> Option<BlocksAndBlobsByRangeResponse<T::EthSpec>> {
        match self.backfill_blocks_and_blobs_requests.entry(request_id) {
            Entry::Occupied(mut entry) => {
                let (_, info) = entry.get_mut();
                match block_or_blob {
                    BlockOrBlob::Block(maybe_block) => info.add_block_response(maybe_block),
                    BlockOrBlob::Blob(maybe_sidecar) => info.add_sidecar_response(maybe_sidecar),
                }
                if info.is_finished() {
                    // If the request is finished, dequeue everything
                    let (batch_id, info) = entry.remove();

                    let responses = info.into_responses();
                    Some(BlocksAndBlobsByRangeResponse {
                        batch_id,
                        responses,
                    })
                } else {
                    None
                }
            }
            Entry::Vacant(_) => None,
        }
    }

    pub fn block_lookup_request(
        &self,
        id: SingleLookupReqId,
        peer_id: PeerId,
        request: BlocksByRootRequest,
        lookup_type: LookupType,
    ) -> Result<(), &'static str> {
        let sync_id = match lookup_type {
            LookupType::Current => SyncRequestId::SingleBlock { id },
            LookupType::Parent => SyncRequestId::ParentLookup { id },
        };
        let request_id = RequestId::Sync(sync_id);

        debug!(
            self.log,
            "Sending BlocksByRoot Request";
            "method" => "BlocksByRoot",
            "block_roots" => ?request.block_roots().to_vec(),
            "peer" => %peer_id,
            "lookup_type" => ?lookup_type
        );

        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request: Request::BlocksByRoot(request),
            request_id,
        })?;
        Ok(())
    }

    pub fn blob_lookup_request(
        &self,
        id: SingleLookupReqId,
        blob_peer_id: PeerId,
        blob_request: BlobsByRootRequest,
        lookup_type: LookupType,
    ) -> Result<(), &'static str> {
        let sync_id = match lookup_type {
            LookupType::Current => SyncRequestId::SingleBlob { id },
            LookupType::Parent => SyncRequestId::ParentLookupBlob { id },
        };
        let request_id = RequestId::Sync(sync_id);

        if let Some(block_root) = blob_request
            .blob_ids
            .as_slice()
            .first()
            .map(|id| id.block_root)
        {
            let indices = blob_request
                .blob_ids
                .as_slice()
                .iter()
                .map(|id| id.index)
                .collect::<Vec<_>>();
            debug!(
                self.log,
                "Sending BlobsByRoot Request";
                "method" => "BlobsByRoot",
                "block_root" => ?block_root,
                "blob_indices" => ?indices,
                "peer" => %blob_peer_id,
                "lookup_type" => ?lookup_type
            );

            self.send_network_msg(NetworkMessage::SendRequest {
                peer_id: blob_peer_id,
                request: Request::BlobsByRoot(blob_request),
                request_id,
            })?;
        }
        Ok(())
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
    pub fn report_peer(&self, peer_id: PeerId, action: PeerAction, msg: &'static str) {
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
    pub fn subscribe_core_topics(&self) {
        self.network_send
            .send(NetworkMessage::SubscribeCoreTopics)
            .unwrap_or_else(|e| {
                warn!(self.log, "Could not subscribe to core topics."; "error" => %e);
            });
    }

    /// Sends an arbitrary network message.
    fn send_network_msg(&self, msg: NetworkMessage<T::EthSpec>) -> Result<(), &'static str> {
        self.network_send.send(msg).map_err(|_| {
            debug!(self.log, "Could not send message to the network service");
            "Network channel send Failed"
        })
    }

    pub fn beacon_processor_if_enabled(&self) -> Option<&Arc<NetworkBeaconProcessor<T>>> {
        self.is_execution_engine_online()
            .then_some(&self.network_beacon_processor)
    }

    pub fn beacon_processor(&self) -> &Arc<NetworkBeaconProcessor<T>> {
        &self.network_beacon_processor
    }

    pub fn next_id(&mut self) -> Id {
        let id = self.request_id;
        self.request_id += 1;
        id
    }

    /// Check whether a batch for this epoch (and only this epoch) should request just blocks or
    /// blocks and blobs.
    pub fn batch_type(&self, epoch: types::Epoch) -> ByRangeRequestType {
        // Induces a compile time panic if this doesn't hold true.
        #[allow(clippy::assertions_on_constants)]
        const _: () = assert!(
            super::backfill_sync::BACKFILL_EPOCHS_PER_BATCH == 1
                && super::range_sync::EPOCHS_PER_BATCH == 1,
            "To deal with alignment with deneb boundaries, batches need to be of just one epoch"
        );

        if let Some(data_availability_boundary) = self.chain.data_availability_boundary() {
            if epoch >= data_availability_boundary {
                ByRangeRequestType::BlocksAndBlobs
            } else {
                ByRangeRequestType::Blocks
            }
        } else {
            ByRangeRequestType::Blocks
        }
    }

    pub fn insert_range_blocks_and_blobs_request(
        &mut self,
        id: Id,
        request: BlocksAndBlobsByRangeRequest<T::EthSpec>,
    ) {
        self.range_blocks_and_blobs_requests.insert(id, request);
    }

    pub fn insert_backfill_blocks_and_blobs_requests(
        &mut self,
        id: Id,
        batch_id: BatchId,
        request: BlocksAndBlobsRequestInfo<T::EthSpec>,
    ) {
        self.backfill_blocks_and_blobs_requests
            .insert(id, (batch_id, request));
    }
}
