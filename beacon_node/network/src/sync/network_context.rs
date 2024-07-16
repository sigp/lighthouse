//! Provides network functionality for the Syncing thread. This fundamentally wraps a network
//! channel and stores a global RPC ID to perform requests.

use self::requests::{ActiveBlobsByRootRequest, ActiveBlocksByRootRequest};
pub use self::requests::{BlobsByRootSingleBlockRequest, BlocksByRootSingleRequest};
use super::block_sidecar_coupling::BlocksAndBlobsRequestInfo;
use super::range_sync::{BatchId, ByRangeRequestType, ChainId};
use crate::metrics;
use crate::network_beacon_processor::NetworkBeaconProcessor;
use crate::service::NetworkMessage;
use crate::status::ToStatusMessage;
use crate::sync::block_lookups::SingleLookupId;
use crate::sync::manager::BlockProcessType;
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockProcessStatus, EngineState};
use fnv::FnvHashMap;
use lighthouse_network::rpc::methods::BlobsByRangeRequest;
use lighthouse_network::rpc::{BlocksByRangeRequest, GoodbyeReason, RPCError};
use lighthouse_network::service::api_types::{AppRequestId, Id, SingleLookupReqId, SyncRequestId};
use lighthouse_network::{Client, NetworkGlobals, PeerAction, PeerId, ReportSource, Request};
pub use requests::LookupVerifyError;
use slog::{debug, error, trace, warn};
use std::collections::hash_map::Entry;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use types::blob_sidecar::FixedBlobSidecarList;
use types::{BlobSidecar, EthSpec, Hash256, SignedBeaconBlock};

mod requests;

pub struct BlocksAndBlobsByRangeResponse<E: EthSpec> {
    pub sender_id: RangeRequestId,
    pub responses: Result<Vec<RpcBlock<E>>, String>,
    pub request_type: ByRangeRequestType,
}

#[derive(Debug, Clone, Copy)]
pub enum RangeRequestId {
    RangeSync {
        chain_id: ChainId,
        batch_id: BatchId,
    },
    BackfillSync {
        batch_id: BatchId,
    },
}

#[derive(Debug)]
pub enum RpcEvent<T> {
    StreamTermination,
    Response(T, Duration),
    RPCError(RPCError),
}

pub type RpcResponseResult<T> = Result<(T, Duration), RpcResponseError>;

pub enum RpcResponseError {
    RpcError(RPCError),
    VerifyError(LookupVerifyError),
}

#[derive(Debug, PartialEq, Eq)]
pub enum RpcRequestSendError {
    /// Network channel send failed
    NetworkSendError,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SendErrorProcessor {
    SendError,
    ProcessorNotAvailable,
}

impl std::fmt::Display for RpcResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            RpcResponseError::RpcError(e) => write!(f, "RPC Error: {:?}", e),
            RpcResponseError::VerifyError(e) => write!(f, "Lookup Verify Error: {:?}", e),
        }
    }
}

impl From<RPCError> for RpcResponseError {
    fn from(e: RPCError) -> Self {
        RpcResponseError::RpcError(e)
    }
}

impl From<LookupVerifyError> for RpcResponseError {
    fn from(e: LookupVerifyError) -> Self {
        RpcResponseError::VerifyError(e)
    }
}

/// Sequential ID that uniquely identifies ReqResp outgoing requests
pub type ReqId = u32;

pub enum LookupRequestResult {
    /// A request is sent. Sync MUST receive an event from the network in the future for either:
    /// completed response or failed request
    RequestSent(ReqId),
    /// No request is sent, and no further action is necessary to consider this request completed
    NoRequestNeeded,
    /// No request is sent, but the request is not completed. Sync MUST receive some future event
    /// that makes progress on the request. For example: request is processing from a different
    /// source (i.e. block received from gossip) and sync MUST receive an event with that processing
    /// result.
    Pending(&'static str),
}

/// Wraps a Network channel to employ various RPC related network functionality for the Sync manager. This includes management of a global RPC request Id.
pub struct SyncNetworkContext<T: BeaconChainTypes> {
    /// The network channel to relay messages to the Network service.
    network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,

    /// A sequential ID for all RPC requests.
    request_id: Id,

    /// A mapping of active BlocksByRoot requests, including both current slot and parent lookups.
    blocks_by_root_requests: FnvHashMap<SingleLookupReqId, ActiveBlocksByRootRequest>,

    /// A mapping of active BlobsByRoot requests, including both current slot and parent lookups.
    blobs_by_root_requests: FnvHashMap<SingleLookupReqId, ActiveBlobsByRootRequest<T::EthSpec>>,

    /// BlocksByRange requests paired with BlobsByRange
    range_blocks_and_blobs_requests:
        FnvHashMap<Id, (RangeRequestId, BlocksAndBlobsRequestInfo<T::EthSpec>)>,

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
pub enum BlockOrBlob<E: EthSpec> {
    Block(Option<Arc<SignedBeaconBlock<E>>>),
    Blob(Option<Arc<BlobSidecar<E>>>),
}

impl<E: EthSpec> From<Option<Arc<SignedBeaconBlock<E>>>> for BlockOrBlob<E> {
    fn from(block: Option<Arc<SignedBeaconBlock<E>>>) -> Self {
        BlockOrBlob::Block(block)
    }
}

impl<E: EthSpec> From<Option<Arc<BlobSidecar<E>>>> for BlockOrBlob<E> {
    fn from(blob: Option<Arc<BlobSidecar<E>>>) -> Self {
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
            blocks_by_root_requests: <_>::default(),
            blobs_by_root_requests: <_>::default(),
            range_blocks_and_blobs_requests: FnvHashMap::default(),
            network_beacon_processor,
            chain,
            log,
        }
    }

    /// Returns the ids of all the requests made to the given peer_id.
    pub fn peer_disconnected(&mut self, peer_id: &PeerId) -> Vec<SyncRequestId> {
        let failed_range_ids =
            self.range_blocks_and_blobs_requests
                .iter()
                .filter_map(|(id, request)| {
                    if request.1.peer_id == *peer_id {
                        Some(SyncRequestId::RangeBlockAndBlobs { id: *id })
                    } else {
                        None
                    }
                });

        let failed_block_ids = self
            .blocks_by_root_requests
            .iter()
            .filter_map(|(id, request)| {
                if request.peer_id == *peer_id {
                    Some(SyncRequestId::SingleBlock { id: *id })
                } else {
                    None
                }
            });
        let failed_blob_ids = self
            .blobs_by_root_requests
            .iter()
            .filter_map(|(id, request)| {
                if request.peer_id == *peer_id {
                    Some(SyncRequestId::SingleBlob { id: *id })
                } else {
                    None
                }
            });

        failed_range_ids
            .chain(failed_block_ids)
            .chain(failed_blob_ids)
            .collect()
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
            let request_id = AppRequestId::Router;
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
    ) -> Result<Id, RpcRequestSendError> {
        let id = self.next_id();
        trace!(
            self.log,
            "Sending BlocksByRange request";
            "method" => "BlocksByRange",
            "count" => request.count(),
            "peer" => %peer_id,
        );
        self.network_send
            .send(NetworkMessage::SendRequest {
                peer_id,
                request: Request::BlocksByRange(request.clone()),
                request_id: AppRequestId::Sync(SyncRequestId::RangeBlockAndBlobs { id }),
            })
            .map_err(|_| RpcRequestSendError::NetworkSendError)?;

        if matches!(batch_type, ByRangeRequestType::BlocksAndBlobs) {
            debug!(
                self.log,
                "Sending BlobsByRange requests";
                "method" => "BlobsByRange",
                "count" => request.count(),
                "peer" => %peer_id,
            );

            // Create the blob request based on the blocks request.
            self.network_send
                .send(NetworkMessage::SendRequest {
                    peer_id,
                    request: Request::BlobsByRange(BlobsByRangeRequest {
                        start_slot: *request.start_slot(),
                        count: *request.count(),
                    }),
                    request_id: AppRequestId::Sync(SyncRequestId::RangeBlockAndBlobs { id }),
                })
                .map_err(|_| RpcRequestSendError::NetworkSendError)?;
        }

        Ok(id)
    }

    /// A blocks by range request sent by the range sync algorithm
    pub fn blocks_and_blobs_by_range_request(
        &mut self,
        peer_id: PeerId,
        batch_type: ByRangeRequestType,
        request: BlocksByRangeRequest,
        sender_id: RangeRequestId,
    ) -> Result<Id, RpcRequestSendError> {
        let id = self.blocks_by_range_request(peer_id, batch_type, request)?;
        self.range_blocks_and_blobs_requests.insert(
            id,
            (
                sender_id,
                BlocksAndBlobsRequestInfo::new(batch_type, peer_id),
            ),
        );
        Ok(id)
    }

    pub fn range_request_failed(&mut self, request_id: Id) -> Option<RangeRequestId> {
        let sender_id = self
            .range_blocks_and_blobs_requests
            .remove(&request_id)
            .map(|(sender_id, _info)| sender_id);
        if let Some(sender_id) = sender_id {
            debug!(
                self.log,
                "Sync range request failed";
                "request_id" => request_id,
                "sender_id" => ?sender_id
            );
            Some(sender_id)
        } else {
            debug!(self.log, "Sync range request failed"; "request_id" => request_id);
            None
        }
    }

    /// Received a blocks by range or blobs by range response for a request that couples blocks '
    /// and blobs.
    pub fn range_block_and_blob_response(
        &mut self,
        request_id: Id,
        block_or_blob: BlockOrBlob<T::EthSpec>,
    ) -> Option<BlocksAndBlobsByRangeResponse<T::EthSpec>> {
        let Entry::Occupied(mut entry) = self.range_blocks_and_blobs_requests.entry(request_id)
        else {
            metrics::inc_counter_vec(&metrics::SYNC_UNKNOWN_NETWORK_REQUESTS, &["range_blocks"]);
            return None;
        };

        let (_, info) = entry.get_mut();
        match block_or_blob {
            BlockOrBlob::Block(maybe_block) => info.add_block_response(maybe_block),
            BlockOrBlob::Blob(maybe_sidecar) => info.add_sidecar_response(maybe_sidecar),
        }
        if info.is_finished() {
            // If the request is finished, dequeue everything
            let (sender_id, info) = entry.remove();
            let request_type = info.get_request_type();
            Some(BlocksAndBlobsByRangeResponse {
                sender_id,
                request_type,
                responses: info.into_responses(),
            })
        } else {
            None
        }
    }

    /// Request block of `block_root` if necessary by checking:
    /// - If the da_checker has a pending block from gossip or a previous request
    ///
    /// Returns false if no request was made, because the block is already imported
    pub fn block_lookup_request(
        &mut self,
        lookup_id: SingleLookupId,
        peer_id: PeerId,
        block_root: Hash256,
    ) -> Result<LookupRequestResult, RpcRequestSendError> {
        match self.chain.get_block_process_status(&block_root) {
            // Unknown block, continue request to download
            BlockProcessStatus::Unknown => {}
            // Block is known are currently processing, expect a future event with the result of
            // processing.
            BlockProcessStatus::NotValidated { .. } => {
                // Lookup sync event safety: If the block is currently in the processing cache, we
                // are guaranteed to receive a `SyncMessage::GossipBlockProcessResult` that will
                // make progress on this lookup
                return Ok(LookupRequestResult::Pending("block in processing cache"));
            }
            // Block is fully validated. If it's not yet imported it's waiting for missing block
            // components. Consider this request completed and do nothing.
            BlockProcessStatus::ExecutionValidated { .. } => {
                return Ok(LookupRequestResult::NoRequestNeeded)
            }
        }

        let req_id = self.next_id();
        let id = SingleLookupReqId { lookup_id, req_id };

        debug!(
            self.log,
            "Sending BlocksByRoot Request";
            "method" => "BlocksByRoot",
            "block_root" => ?block_root,
            "peer" => %peer_id,
            "id" => ?id
        );

        let request = BlocksByRootSingleRequest(block_root);

        // Lookup sync event safety: If network_send.send() returns Ok(_) we are guaranteed that
        // eventually at least one this 3 events will be received:
        // - StreamTermination(request_id): handled by `Self::on_single_block_response`
        // - RPCError(request_id): handled by `Self::on_single_block_response`
        // - Disconnect(peer_id) handled by `Self::peer_disconnected``which converts it to a
        // ` RPCError(request_id)`event handled by the above method
        self.network_send
            .send(NetworkMessage::SendRequest {
                peer_id,
                request: Request::BlocksByRoot(request.into_request(&self.chain.spec)),
                request_id: AppRequestId::Sync(SyncRequestId::SingleBlock { id }),
            })
            .map_err(|_| RpcRequestSendError::NetworkSendError)?;

        self.blocks_by_root_requests
            .insert(id, ActiveBlocksByRootRequest::new(request, peer_id));

        Ok(LookupRequestResult::RequestSent(req_id))
    }

    /// Request necessary blobs for `block_root`. Requests only the necessary blobs by checking:
    /// - If we have a downloaded but not yet processed block
    /// - If the da_checker has a pending block
    /// - If the da_checker has pending blobs from gossip
    ///
    /// Returns false if no request was made, because we don't need to import (more) blobs.
    pub fn blob_lookup_request(
        &mut self,
        lookup_id: SingleLookupId,
        peer_id: PeerId,
        block_root: Hash256,
        downloaded_block_expected_blobs: Option<usize>,
    ) -> Result<LookupRequestResult, RpcRequestSendError> {
        let Some(expected_blobs) = downloaded_block_expected_blobs.or_else(|| {
            // If the block is already being processed or fully validated, retrieve how many blobs
            // it expects. Consider any stage of the block. If the block root has been validated, we
            // can assert that this is the correct value of `blob_kzg_commitments_count`.
            match self.chain.get_block_process_status(&block_root) {
                BlockProcessStatus::Unknown => None,
                BlockProcessStatus::NotValidated(block)
                | BlockProcessStatus::ExecutionValidated(block) => Some(block.num_expected_blobs()),
            }
        }) else {
            // Wait to download the block before downloading blobs. Then we can be sure that the
            // block has data, so there's no need to do "blind" requests for all possible blobs and
            // latter handle the case where if the peer sent no blobs, penalize.
            // - if `downloaded_block_expected_blobs` is Some = block is downloading or processing.
            // - if `num_expected_blobs` returns Some = block is processed.
            //
            // Lookup sync event safety: Reaching this code means that a block is not in any pre-import
            // cache nor in the request state of this lookup. Therefore, the block must either: (1) not
            // be downloaded yet or (2) the block is already imported into the fork-choice.
            // In case (1) the lookup must either successfully download the block or get dropped.
            // In case (2) the block will be downloaded, processed, reach `BlockIsAlreadyKnown` and
            // get dropped as completed.
            return Ok(LookupRequestResult::Pending("waiting for block download"));
        };

        let imported_blob_indexes = self
            .chain
            .data_availability_checker
            .imported_blob_indexes(&block_root)
            .unwrap_or_default();
        // Include only the blob indexes not yet imported (received through gossip)
        let indices = (0..expected_blobs as u64)
            .filter(|index| !imported_blob_indexes.contains(index))
            .collect::<Vec<_>>();

        if indices.is_empty() {
            // No blobs required, do not issue any request
            return Ok(LookupRequestResult::NoRequestNeeded);
        }

        let req_id = self.next_id();
        let id = SingleLookupReqId { lookup_id, req_id };

        debug!(
            self.log,
            "Sending BlobsByRoot Request";
            "method" => "BlobsByRoot",
            "block_root" => ?block_root,
            "blob_indices" => ?indices,
            "peer" => %peer_id,
            "id" => ?id
        );

        let request = BlobsByRootSingleBlockRequest {
            block_root,
            indices,
        };

        // Lookup sync event safety: Refer to `Self::block_lookup_request` `network_send.send` call
        self.network_send
            .send(NetworkMessage::SendRequest {
                peer_id,
                request: Request::BlobsByRoot(request.clone().into_request(&self.chain.spec)),
                request_id: AppRequestId::Sync(SyncRequestId::SingleBlob { id }),
            })
            .map_err(|_| RpcRequestSendError::NetworkSendError)?;

        self.blobs_by_root_requests
            .insert(id, ActiveBlobsByRootRequest::new(request, peer_id));

        Ok(LookupRequestResult::RequestSent(req_id))
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
        debug!(self.log, "Sync reporting peer"; "peer_id" => %peer_id, "action" => %action, "msg" => %msg);
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
        sender_id: RangeRequestId,
        info: BlocksAndBlobsRequestInfo<T::EthSpec>,
    ) {
        self.range_blocks_and_blobs_requests
            .insert(id, (sender_id, info));
    }

    // Request handlers

    pub fn on_single_block_response(
        &mut self,
        request_id: SingleLookupReqId,
        peer_id: PeerId,
        block: RpcEvent<Arc<SignedBeaconBlock<T::EthSpec>>>,
    ) -> Option<RpcResponseResult<Arc<SignedBeaconBlock<T::EthSpec>>>> {
        let Entry::Occupied(mut request) = self.blocks_by_root_requests.entry(request_id) else {
            metrics::inc_counter_vec(&metrics::SYNC_UNKNOWN_NETWORK_REQUESTS, &["blocks_by_root"]);
            return None;
        };

        let resp = match block {
            RpcEvent::Response(block, seen_timestamp) => {
                match request.get_mut().add_response(block) {
                    Ok(block) => Ok((block, seen_timestamp)),
                    Err(e) => {
                        // The request must be dropped after receiving an error.
                        request.remove();
                        Err(e.into())
                    }
                }
            }
            RpcEvent::StreamTermination => match request.remove().terminate() {
                Ok(_) => return None,
                Err(e) => Err(e.into()),
            },
            RpcEvent::RPCError(e) => {
                request.remove();
                Err(e.into())
            }
        };

        if let Err(RpcResponseError::VerifyError(e)) = &resp {
            self.report_peer(peer_id, PeerAction::LowToleranceError, e.into());
        }
        Some(resp)
    }

    pub fn on_single_blob_response(
        &mut self,
        request_id: SingleLookupReqId,
        peer_id: PeerId,
        blob: RpcEvent<Arc<BlobSidecar<T::EthSpec>>>,
    ) -> Option<RpcResponseResult<FixedBlobSidecarList<T::EthSpec>>> {
        let Entry::Occupied(mut request) = self.blobs_by_root_requests.entry(request_id) else {
            metrics::inc_counter_vec(&metrics::SYNC_UNKNOWN_NETWORK_REQUESTS, &["blobs_by_root"]);
            return None;
        };

        let resp = match blob {
            RpcEvent::Response(blob, seen_timestamp) => {
                let request = request.get_mut();
                match request.add_response(blob) {
                    Ok(Some(blobs)) => to_fixed_blob_sidecar_list(blobs)
                        .map(|blobs| (blobs, seen_timestamp))
                        .map_err(|e| (e.into(), request.resolve())),
                    Ok(None) => return None,
                    Err(e) => Err((e.into(), request.resolve())),
                }
            }
            RpcEvent::StreamTermination => match request.remove().terminate() {
                Ok(_) => return None,
                // (err, false = not resolved) because terminate returns Ok() if resolved
                Err(e) => Err((e.into(), false)),
            },
            RpcEvent::RPCError(e) => Err((e.into(), request.remove().resolve())),
        };

        match resp {
            Ok(resp) => Some(Ok(resp)),
            // Track if this request has already returned some value downstream. Ensure that
            // downstream code only receives a single Result per request. If the serving peer does
            // multiple penalizable actions per request, downscore and return None. This allows to
            // catch if a peer is returning more blobs than requested or if the excess blobs are
            // invalid.
            Err((e, resolved)) => {
                if let RpcResponseError::VerifyError(e) = &e {
                    self.report_peer(peer_id, PeerAction::LowToleranceError, e.into());
                }
                if resolved {
                    None
                } else {
                    Some(Err(e))
                }
            }
        }
    }

    pub fn send_block_for_processing(
        &self,
        id: Id,
        block_root: Hash256,
        block: RpcBlock<T::EthSpec>,
        duration: Duration,
    ) -> Result<(), SendErrorProcessor> {
        let beacon_processor = self
            .beacon_processor_if_enabled()
            .ok_or(SendErrorProcessor::ProcessorNotAvailable)?;

        debug!(self.log, "Sending block for processing"; "block" => ?block_root, "id" => id);
        // Lookup sync event safety: If `beacon_processor.send_rpc_beacon_block` returns Ok() sync
        // must receive a single `SyncMessage::BlockComponentProcessed` with this process type
        beacon_processor
            .send_rpc_beacon_block(
                block_root,
                block,
                duration,
                BlockProcessType::SingleBlock { id },
            )
            .map_err(|e| {
                error!(
                    self.log,
                    "Failed to send sync block to processor";
                    "error" => ?e
                );
                SendErrorProcessor::SendError
            })
    }

    pub fn send_blobs_for_processing(
        &self,
        id: Id,
        block_root: Hash256,
        blobs: FixedBlobSidecarList<T::EthSpec>,
        duration: Duration,
    ) -> Result<(), SendErrorProcessor> {
        let beacon_processor = self
            .beacon_processor_if_enabled()
            .ok_or(SendErrorProcessor::ProcessorNotAvailable)?;

        debug!(self.log, "Sending blobs for processing"; "block" => ?block_root, "id" => id);
        // Lookup sync event safety: If `beacon_processor.send_rpc_blobs` returns Ok() sync
        // must receive a single `SyncMessage::BlockComponentProcessed` event with this process type
        beacon_processor
            .send_rpc_blobs(
                block_root,
                blobs,
                duration,
                BlockProcessType::SingleBlob { id },
            )
            .map_err(|e| {
                error!(
                    self.log,
                    "Failed to send sync blobs to processor";
                    "error" => ?e
                );
                SendErrorProcessor::SendError
            })
    }

    pub(crate) fn register_metrics(&self) {
        metrics::set_gauge_vec(
            &metrics::SYNC_ACTIVE_NETWORK_REQUESTS,
            &["blocks_by_root"],
            self.blocks_by_root_requests.len() as i64,
        );
        metrics::set_gauge_vec(
            &metrics::SYNC_ACTIVE_NETWORK_REQUESTS,
            &["blobs_by_root"],
            self.blobs_by_root_requests.len() as i64,
        );
        metrics::set_gauge_vec(
            &metrics::SYNC_ACTIVE_NETWORK_REQUESTS,
            &["range_blocks"],
            self.range_blocks_and_blobs_requests.len() as i64,
        );
    }
}

fn to_fixed_blob_sidecar_list<E: EthSpec>(
    blobs: Vec<Arc<BlobSidecar<E>>>,
) -> Result<FixedBlobSidecarList<E>, LookupVerifyError> {
    let mut fixed_list = FixedBlobSidecarList::default();
    for blob in blobs.into_iter() {
        let index = blob.index as usize;
        *fixed_list
            .get_mut(index)
            .ok_or(LookupVerifyError::UnrequestedBlobIndex(index as u64))? = Some(blob)
    }
    Ok(fixed_list)
}
