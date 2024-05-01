//! Provides network functionality for the Syncing thread. This fundamentally wraps a network
//! channel and stores a global RPC ID to perform requests.

use self::requests::{ActiveBlobsByRootRequest, ActiveBlocksByRootRequest};
pub use self::requests::{BlobsByRootSingleBlockRequest, BlocksByRootSingleRequest};
use super::block_sidecar_coupling::BlocksAndBlobsRequestInfo;
use super::manager::{BlockProcessType, Id, RequestId as SyncRequestId};
use super::range_sync::{BatchId, ByRangeRequestType, ChainId};
use crate::network_beacon_processor::NetworkBeaconProcessor;
use crate::service::{NetworkMessage, RequestId};
use crate::status::ToStatusMessage;
use crate::sync::block_lookups::SingleLookupId;
use crate::sync::manager::SingleLookupReqId;
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::validator_monitor::timestamp_now;
use beacon_chain::{BeaconChain, BeaconChainTypes, EngineState};
use fnv::FnvHashMap;
use lighthouse_network::rpc::methods::BlobsByRangeRequest;
use lighthouse_network::rpc::{BlocksByRangeRequest, GoodbyeReason, RPCError};
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

pub type RpcProcessingResult<T> = Result<(T, Duration), LookupFailure>;

pub enum LookupFailure {
    RpcError(RPCError),
    LookupVerifyError(LookupVerifyError),
}

impl std::fmt::Display for LookupFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            LookupFailure::RpcError(e) => write!(f, "RPC Error: {:?}", e),
            LookupFailure::LookupVerifyError(e) => write!(f, "Lookup Verify Error: {:?}", e),
        }
    }
}

impl From<RPCError> for LookupFailure {
    fn from(e: RPCError) -> Self {
        LookupFailure::RpcError(e)
    }
}

impl From<LookupVerifyError> for LookupFailure {
    fn from(e: LookupVerifyError) -> Self {
        LookupFailure::LookupVerifyError(e)
    }
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
    ) -> Result<Id, &'static str> {
        let id = self.next_id();
        trace!(
            self.log,
            "Sending BlocksByRange request";
            "method" => "BlocksByRange",
            "count" => request.count(),
            "peer" => %peer_id,
        );
        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request: Request::BlocksByRange(request.clone()),
            request_id: RequestId::Sync(SyncRequestId::RangeBlockAndBlobs { id }),
        })?;

        if matches!(batch_type, ByRangeRequestType::BlocksAndBlobs) {
            debug!(
                self.log,
                "Sending BlobsByRange requests";
                "method" => "BlobsByRange",
                "count" => request.count(),
                "peer" => %peer_id,
            );

            // Create the blob request based on the blocks request.
            self.send_network_msg(NetworkMessage::SendRequest {
                peer_id,
                request: Request::BlobsByRange(BlobsByRangeRequest {
                    start_slot: *request.start_slot(),
                    count: *request.count(),
                }),
                request_id: RequestId::Sync(SyncRequestId::RangeBlockAndBlobs { id }),
            })?;
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
    ) -> Result<Id, &'static str> {
        let id = self.blocks_by_range_request(peer_id, batch_type, request)?;
        self.range_blocks_and_blobs_requests
            .insert(id, (sender_id, BlocksAndBlobsRequestInfo::new(batch_type)));
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
        match self.range_blocks_and_blobs_requests.entry(request_id) {
            Entry::Occupied(mut entry) => {
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
            Entry::Vacant(_) => None,
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
    ) -> Result<bool, &'static str> {
        if self
            .chain
            .reqresp_pre_import_cache
            .read()
            .contains_key(&block_root)
        {
            return Ok(false);
        }

        let id = SingleLookupReqId {
            lookup_id,
            req_id: self.next_id(),
        };

        debug!(
            self.log,
            "Sending BlocksByRoot Request";
            "method" => "BlocksByRoot",
            "block_root" => ?block_root,
            "peer" => %peer_id,
            "id" => ?id
        );

        let request = BlocksByRootSingleRequest(block_root);

        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request: Request::BlocksByRoot(request.into_request(&self.chain.spec)),
            request_id: RequestId::Sync(SyncRequestId::SingleBlock { id }),
        })?;

        self.blocks_by_root_requests
            .insert(id, ActiveBlocksByRootRequest::new(request));

        Ok(true)
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
    ) -> Result<bool, &'static str> {
        let expected_blobs = downloaded_block_expected_blobs
            .or_else(|| {
                self.chain
                    .data_availability_checker
                    .num_expected_blobs(&block_root)
            })
            .unwrap_or_else(|| {
                // If we don't about the block being requested, attempt to fetch all blobs
                if self
                    .chain
                    .data_availability_checker
                    .da_check_required_for_current_epoch()
                {
                    T::EthSpec::max_blobs_per_block()
                } else {
                    0
                }
            });

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
            return Ok(false);
        }

        let id = SingleLookupReqId {
            lookup_id,
            req_id: self.next_id(),
        };

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

        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request: Request::BlobsByRoot(request.clone().into_request(&self.chain.spec)),
            request_id: RequestId::Sync(SyncRequestId::SingleBlob { id }),
        })?;

        self.blobs_by_root_requests
            .insert(id, ActiveBlobsByRootRequest::new(request));

        Ok(true)
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
        block: RpcEvent<Arc<SignedBeaconBlock<T::EthSpec>>>,
    ) -> Option<RpcProcessingResult<Arc<SignedBeaconBlock<T::EthSpec>>>> {
        let Entry::Occupied(mut request) = self.blocks_by_root_requests.entry(request_id) else {
            return None;
        };

        Some(match block {
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
        })
    }

    pub fn on_single_blob_response(
        &mut self,
        request_id: SingleLookupReqId,
        blob: RpcEvent<Arc<BlobSidecar<T::EthSpec>>>,
    ) -> Option<RpcProcessingResult<FixedBlobSidecarList<T::EthSpec>>> {
        let Entry::Occupied(mut request) = self.blobs_by_root_requests.entry(request_id) else {
            return None;
        };

        Some(match blob {
            RpcEvent::Response(blob, _) => match request.get_mut().add_response(blob) {
                Ok(Some(blobs)) => to_fixed_blob_sidecar_list(blobs)
                    .map(|blobs| (blobs, timestamp_now()))
                    .map_err(Into::into),
                Ok(None) => return None,
                Err(e) => {
                    request.remove();
                    Err(e.into())
                }
            },
            RpcEvent::StreamTermination => {
                // Stream terminator
                match request.remove().terminate() {
                    Some(blobs) => to_fixed_blob_sidecar_list(blobs)
                        .map(|blobs| (blobs, timestamp_now()))
                        .map_err(Into::into),
                    None => return None,
                }
            }
            RpcEvent::RPCError(e) => {
                request.remove();
                Err(e.into())
            }
        })
    }

    pub fn send_block_for_processing(
        &self,
        block_root: Hash256,
        block: RpcBlock<T::EthSpec>,
        duration: Duration,
        process_type: BlockProcessType,
    ) -> Result<(), &'static str> {
        match self.beacon_processor_if_enabled() {
            Some(beacon_processor) => {
                debug!(self.log, "Sending block for processing"; "block" => ?block_root, "process" => ?process_type);
                if let Err(e) = beacon_processor.send_rpc_beacon_block(
                    block_root,
                    block,
                    duration,
                    process_type,
                ) {
                    error!(
                        self.log,
                        "Failed to send sync block to processor";
                        "error" => ?e
                    );
                    Err("beacon processor send failure")
                } else {
                    Ok(())
                }
            }
            None => {
                trace!(self.log, "Dropping block ready for processing. Beacon processor not available"; "block" => %block_root);
                Err("beacon processor unavailable")
            }
        }
    }

    pub fn send_blobs_for_processing(
        &self,
        block_root: Hash256,
        blobs: FixedBlobSidecarList<T::EthSpec>,
        duration: Duration,
        process_type: BlockProcessType,
    ) -> Result<(), &'static str> {
        match self.beacon_processor_if_enabled() {
            Some(beacon_processor) => {
                debug!(self.log, "Sending blobs for processing"; "block" => ?block_root, "process_type" => ?process_type);
                if let Err(e) =
                    beacon_processor.send_rpc_blobs(block_root, blobs, duration, process_type)
                {
                    error!(
                        self.log,
                        "Failed to send sync blobs to processor";
                        "error" => ?e
                    );
                    Err("beacon processor send failure")
                } else {
                    Ok(())
                }
            }
            None => {
                trace!(self.log, "Dropping blobs ready for processing. Beacon processor not available"; "block_root" => %block_root);
                Err("beacon processor unavailable")
            }
        }
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
