//! Provides network functionality for the Syncing thread. This fundamentally wraps a network
//! channel and stores a global RPC ID to perform requests.

use self::custody::{ActiveCustodyRequest, Error as CustodyRequestError};
use self::requests::{ActiveBlobsByRootRequest, ActiveBlocksByRootRequest};
pub use self::requests::{BlocksByRootSingleRequest, DataColumnsByRootSingleBlockRequest};
use super::block_sidecar_coupling::RangeBlockComponentsRequest;
use super::manager::BlockProcessType;
use super::range_sync::{BatchId, ByRangeRequestType, ChainId};
use crate::metrics;
use crate::network_beacon_processor::NetworkBeaconProcessor;
use crate::service::NetworkMessage;
use crate::status::ToStatusMessage;
use crate::sync::block_lookups::SingleLookupId;
use crate::sync::network_context::requests::BlobsByRootSingleBlockRequest;
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockProcessStatus, EngineState};
use fnv::FnvHashMap;
use lighthouse_network::rpc::methods::{BlobsByRangeRequest, DataColumnsByRangeRequest};
use lighthouse_network::rpc::{BlocksByRangeRequest, GoodbyeReason, RPCError};
use lighthouse_network::service::api_types::{
    AppRequestId, CustodyId, CustodyRequester, DataColumnsByRootRequestId,
    DataColumnsByRootRequester, Id, SingleLookupReqId, SyncRequestId,
};
use lighthouse_network::{Client, NetworkGlobals, PeerAction, PeerId, ReportSource, Request};
use rand::seq::SliceRandom;
use rand::thread_rng;
use requests::ActiveDataColumnsByRootRequest;
pub use requests::LookupVerifyError;
use slog::{debug, error, warn};
use slot_clock::SlotClock;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use types::blob_sidecar::FixedBlobSidecarList;
use types::{
    BlobSidecar, ColumnIndex, DataColumnSidecar, DataColumnSidecarList, EthSpec, Hash256,
    SignedBeaconBlock, Slot,
};

pub mod custody;
mod requests;

pub struct BlocksAndBlobsByRangeResponse<E: EthSpec> {
    pub sender_id: RangeRequestId,
    pub responses: Result<Vec<RpcBlock<E>>, String>,
    pub expects_blobs: bool,
    pub expects_custody_columns: Option<Vec<ColumnIndex>>,
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

#[derive(Debug)]
pub enum RpcResponseError {
    RpcError(RPCError),
    VerifyError(LookupVerifyError),
    CustodyRequestError(CustodyRequestError),
}

#[derive(Debug, PartialEq, Eq)]
pub enum RpcRequestSendError {
    /// Network channel send failed
    NetworkSendError,
    NoCustodyPeers,
    CustodyRequestError(custody::Error),
    SlotClockError,
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
            RpcResponseError::CustodyRequestError(e) => write!(f, "Custody Request Error: {:?}", e),
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

/// Represents a group of peers that served a block component.
#[derive(Clone, Debug)]
pub struct PeerGroup {
    /// Peers group by which indexed section of the block component they served. For example:
    /// - PeerA served = [blob index 0, blob index 2]
    /// - PeerA served = [blob index 1]
    peers: HashMap<PeerId, Vec<usize>>,
}

impl PeerGroup {
    /// Return a peer group where a single peer returned all parts of a block component. For
    /// example, a block has a single component (the block = index 0/1).
    pub fn from_single(peer: PeerId) -> Self {
        Self {
            peers: HashMap::from_iter([(peer, vec![0])]),
        }
    }
    pub fn from_set(peers: HashMap<PeerId, Vec<usize>>) -> Self {
        Self { peers }
    }
    pub fn all(&self) -> impl Iterator<Item = &PeerId> + '_ {
        self.peers.keys()
    }
}

/// Sequential ID that uniquely identifies ReqResp outgoing requests
pub type ReqId = u32;

pub enum LookupRequestResult<I = ReqId> {
    /// A request is sent. Sync MUST receive an event from the network in the future for either:
    /// completed response or failed request
    RequestSent(I),
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

    /// Mapping of active custody column requests for a block root
    custody_by_root_requests: FnvHashMap<CustodyRequester, ActiveCustodyRequest<T>>,

    /// A mapping of active DataColumnsByRoot requests
    data_columns_by_root_requests:
        FnvHashMap<DataColumnsByRootRequestId, ActiveDataColumnsByRootRequest<T::EthSpec>>,

    /// BlocksByRange requests paired with BlobsByRange
    range_block_components_requests:
        FnvHashMap<Id, (RangeRequestId, RangeBlockComponentsRequest<T::EthSpec>)>,

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
    CustodyColumns(Option<Arc<DataColumnSidecar<E>>>),
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
            data_columns_by_root_requests: <_>::default(),
            custody_by_root_requests: <_>::default(),
            range_block_components_requests: FnvHashMap::default(),
            network_beacon_processor,
            chain,
            log,
        }
    }

    /// Returns the ids of all the requests made to the given peer_id.
    pub fn peer_disconnected(&mut self, peer_id: &PeerId) -> Vec<SyncRequestId> {
        let failed_range_ids =
            self.range_block_components_requests
                .iter()
                .filter_map(|(id, request)| {
                    if request.1.peer_ids.contains(peer_id) {
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
        let failed_data_column_by_root_ids =
            self.data_columns_by_root_requests
                .iter()
                .filter_map(|(req_id, request)| {
                    if request.peer_id == *peer_id {
                        Some(SyncRequestId::DataColumnsByRoot(*req_id, request.requester))
                    } else {
                        None
                    }
                });

        failed_range_ids
            .chain(failed_block_ids)
            .chain(failed_blob_ids)
            .chain(failed_data_column_by_root_ids)
            .collect()
    }

    pub fn get_custodial_peers(&self, column_index: ColumnIndex) -> Vec<PeerId> {
        self.network_globals()
            .custody_peers_for_column(column_index)
    }

    pub fn get_random_custodial_peer(&self, column_index: ColumnIndex) -> Option<PeerId> {
        self.get_custodial_peers(column_index)
            .choose(&mut thread_rng())
            .cloned()
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

    /// A blocks by range request sent by the range sync algorithm
    pub fn block_components_by_range_request(
        &mut self,
        peer_id: PeerId,
        batch_type: ByRangeRequestType,
        request: BlocksByRangeRequest,
        sender_id: RangeRequestId,
    ) -> Result<Id, RpcRequestSendError> {
        let epoch = Slot::new(*request.start_slot()).epoch(T::EthSpec::slots_per_epoch());
        let id = self.next_id();
        let mut requested_peers = vec![peer_id];
        debug!(
            self.log,
            "Sending BlocksByRange request";
            "method" => "BlocksByRange",
            "count" => request.count(),
            "epoch" => epoch,
            "peer" => %peer_id,
        );
        self.network_send
            .send(NetworkMessage::SendRequest {
                peer_id,
                request: Request::BlocksByRange(request.clone()),
                request_id: AppRequestId::Sync(SyncRequestId::RangeBlockAndBlobs { id }),
            })
            .map_err(|_| RpcRequestSendError::NetworkSendError)?;

        let expected_blobs = if matches!(batch_type, ByRangeRequestType::BlocksAndBlobs) {
            debug!(
                self.log,
                "Sending BlobsByRange requests";
                "method" => "BlobsByRange",
                "count" => request.count(),
                "epoch" => epoch,
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
            true
        } else {
            false
        };

        let (expects_custody_columns, num_of_custody_column_req) =
            if matches!(batch_type, ByRangeRequestType::BlocksAndColumns) {
                let custody_indexes = self.network_globals().custody_columns();
                let mut num_of_custody_column_req = 0;

                for (peer_id, columns_by_range_request) in
                    self.make_columns_by_range_requests(request, &custody_indexes)?
                {
                    requested_peers.push(peer_id);

                    debug!(
                        self.log,
                        "Sending DataColumnsByRange requests";
                        "method" => "DataColumnsByRange",
                        "count" => columns_by_range_request.count,
                        "epoch" => epoch,
                        "columns" => ?columns_by_range_request.columns,
                        "peer" => %peer_id,
                    );

                    self.send_network_msg(NetworkMessage::SendRequest {
                        peer_id,
                        request: Request::DataColumnsByRange(columns_by_range_request),
                        request_id: AppRequestId::Sync(SyncRequestId::RangeBlockAndBlobs { id }),
                    })
                    .map_err(|_| RpcRequestSendError::NetworkSendError)?;

                    num_of_custody_column_req += 1;
                }

                (Some(custody_indexes), Some(num_of_custody_column_req))
            } else {
                (None, None)
            };

        let info = RangeBlockComponentsRequest::new(
            expected_blobs,
            expects_custody_columns,
            num_of_custody_column_req,
            requested_peers,
        );
        self.range_block_components_requests
            .insert(id, (sender_id, info));
        Ok(id)
    }

    fn make_columns_by_range_requests(
        &self,
        request: BlocksByRangeRequest,
        custody_indexes: &Vec<ColumnIndex>,
    ) -> Result<HashMap<PeerId, DataColumnsByRangeRequest>, RpcRequestSendError> {
        let mut peer_id_to_request_map = HashMap::new();

        for column_index in custody_indexes {
            // TODO(das): The peer selection logic here needs to be improved - we should probably
            // avoid retrying from failed peers, however `BatchState` currently only tracks the peer
            // serving the blocks.
            let Some(custody_peer) = self.get_random_custodial_peer(*column_index) else {
                // TODO(das): this will be pretty bad UX. To improve we should:
                // - Attempt to fetch custody requests first, before requesting blocks
                // - Handle the no peers case gracefully, maybe add some timeout and give a few
                //   minutes / seconds to the peer manager to locate peers on this subnet before
                //   abandoing progress on the chain completely.
                return Err(RpcRequestSendError::NoCustodyPeers);
            };

            let columns_by_range_request = peer_id_to_request_map
                .entry(custody_peer)
                .or_insert_with(|| DataColumnsByRangeRequest {
                    start_slot: *request.start_slot(),
                    count: *request.count(),
                    columns: vec![],
                });

            columns_by_range_request.columns.push(*column_index);
        }

        Ok(peer_id_to_request_map)
    }

    pub fn range_request_failed(&mut self, request_id: Id) -> Option<RangeRequestId> {
        let sender_id = self
            .range_block_components_requests
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
        let Entry::Occupied(mut entry) = self.range_block_components_requests.entry(request_id)
        else {
            metrics::inc_counter_vec(&metrics::SYNC_UNKNOWN_NETWORK_REQUESTS, &["range_blocks"]);
            return None;
        };

        let (_, info) = entry.get_mut();
        match block_or_blob {
            BlockOrBlob::Block(maybe_block) => info.add_block_response(maybe_block),
            BlockOrBlob::Blob(maybe_sidecar) => info.add_sidecar_response(maybe_sidecar),
            BlockOrBlob::CustodyColumns(column) => info.add_data_column(column),
        }
        if info.is_finished() {
            // If the request is finished, dequeue everything
            let (sender_id, info) = entry.remove();
            let (expects_blobs, expects_custody_columns) = info.get_requirements();
            Some(BlocksAndBlobsByRangeResponse {
                sender_id,
                responses: info.into_responses(&self.chain.spec),
                expects_blobs,
                expects_custody_columns,
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
        downloaded_block: Option<Arc<SignedBeaconBlock<T::EthSpec>>>,
    ) -> Result<LookupRequestResult, RpcRequestSendError> {
        // Check if we are into deneb, and before peerdas
        if !self
            .chain
            .data_availability_checker
            .blobs_required_for_epoch(
                // TODO(das): use the block's slot
                self.chain
                    .slot_clock
                    .now_or_genesis()
                    .ok_or(RpcRequestSendError::SlotClockError)?
                    .epoch(T::EthSpec::slots_per_epoch()),
            )
        {
            return Ok(LookupRequestResult::NoRequestNeeded);
        }
        let Some(block) = downloaded_block.or_else(|| {
            // If the block is already being processed or fully validated, retrieve how many blobs
            // it expects. Consider any stage of the block. If the block root has been validated, we
            // can assert that this is the correct value of `blob_kzg_commitments_count`.
            match self.chain.get_block_process_status(&block_root) {
                BlockProcessStatus::Unknown => None,
                BlockProcessStatus::NotValidated(block)
                | BlockProcessStatus::ExecutionValidated(block) => Some(block.clone()),
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
        let expected_blobs = block.num_expected_blobs();
        let block_epoch = block.slot().epoch(T::EthSpec::slots_per_epoch());

        // Check if we are into peerdas
        if !self.chain.should_fetch_blobs(block_epoch) {
            return Ok(LookupRequestResult::NoRequestNeeded);
        }

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

    /// Request to send a single `data_columns_by_root` request to the network.
    pub fn data_column_lookup_request(
        &mut self,
        requester: DataColumnsByRootRequester,
        peer_id: PeerId,
        request: DataColumnsByRootSingleBlockRequest,
    ) -> Result<LookupRequestResult<DataColumnsByRootRequestId>, &'static str> {
        let req_id = DataColumnsByRootRequestId(self.next_id());
        debug!(
            self.log,
            "Sending DataColumnsByRoot Request";
            "method" => "DataColumnsByRoot",
            "block_root" => ?request.block_root,
            "indices" => ?request.indices,
            "peer" => %peer_id,
            "requester" => ?requester,
            "req_id" => %req_id,
        );

        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request: Request::DataColumnsByRoot(request.clone().into_request(&self.chain.spec)),
            request_id: AppRequestId::Sync(SyncRequestId::DataColumnsByRoot(req_id, requester)),
        })?;

        self.data_columns_by_root_requests.insert(
            req_id,
            ActiveDataColumnsByRootRequest::new(request, peer_id, requester),
        );

        Ok(LookupRequestResult::RequestSent(req_id))
    }

    /// Request to fetch all needed custody columns of a specific block. This function may not send
    /// any request to the network if no columns have to be fetched based on the import state of the
    /// node. A custody request is a "super request" that may trigger 0 or more `data_columns_by_root`
    /// requests.
    pub fn custody_lookup_request(
        &mut self,
        lookup_id: SingleLookupId,
        block_root: Hash256,
        downloaded_block: Option<Arc<SignedBeaconBlock<T::EthSpec>>>,
    ) -> Result<LookupRequestResult, RpcRequestSendError> {
        let Some(block) =
            downloaded_block.or_else(|| match self.chain.get_block_process_status(&block_root) {
                BlockProcessStatus::Unknown => None,
                BlockProcessStatus::NotValidated(block)
                | BlockProcessStatus::ExecutionValidated(block) => Some(block.clone()),
            })
        else {
            // Wait to download the block before downloading columns. Then we can be sure that the
            // block has data, so there's no need to do "blind" requests for all possible columns and
            // latter handle the case where if the peer sent no columns, penalize.
            // - if `downloaded_block_expected_blobs` is Some = block is downloading or processing.
            // - if `num_expected_blobs` returns Some = block is processed.
            return Ok(LookupRequestResult::Pending("waiting for block download"));
        };
        let expected_blobs = block.num_expected_blobs();
        let block_epoch = block.slot().epoch(T::EthSpec::slots_per_epoch());

        // Check if we are into peerdas
        if !self.chain.should_fetch_custody_columns(block_epoch) {
            return Ok(LookupRequestResult::NoRequestNeeded);
        }

        // No data required for this block
        if expected_blobs == 0 {
            return Ok(LookupRequestResult::NoRequestNeeded);
        }

        let custody_indexes_imported = self
            .chain
            .data_availability_checker
            .imported_custody_column_indexes(&block_root)
            .unwrap_or_default();

        let custody_indexes_duty = self.network_globals().custody_columns();

        // Include only the blob indexes not yet imported (received through gossip)
        let custody_indexes_to_fetch = custody_indexes_duty
            .into_iter()
            .filter(|index| !custody_indexes_imported.contains(index))
            .collect::<Vec<_>>();

        if custody_indexes_to_fetch.is_empty() {
            // No indexes required, do not issue any request
            return Ok(LookupRequestResult::NoRequestNeeded);
        }

        let req_id = self.next_id();
        let id = SingleLookupReqId { lookup_id, req_id };

        debug!(
            self.log,
            "Starting custody columns request";
            "block_root" => ?block_root,
            "indices" => ?custody_indexes_to_fetch,
            "id" => ?id
        );

        let requester = CustodyRequester(id);
        let mut request = ActiveCustodyRequest::new(
            block_root,
            // TODO(das): req_id is duplicated here, also present in id
            CustodyId { requester, req_id },
            &custody_indexes_to_fetch,
            self.log.clone(),
        );

        // TODO(das): start request
        // Note that you can only send, but not handle a response here
        match request.continue_requests(self) {
            Ok(_) => {
                // Ignoring the result of `continue_requests` is okay. A request that has just been
                // created cannot return data immediately, it must send some request to the network
                // first. And there must exist some request, `custody_indexes_to_fetch` is not empty.
                self.custody_by_root_requests.insert(requester, request);
                Ok(LookupRequestResult::RequestSent(req_id))
            }
            // TODO(das): handle this error properly
            Err(e) => Err(RpcRequestSendError::CustodyRequestError(e)),
        }
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

        if self
            .chain
            .data_availability_checker
            .data_columns_required_for_epoch(epoch)
        {
            ByRangeRequestType::BlocksAndColumns
        } else if self
            .chain
            .data_availability_checker
            .blobs_required_for_epoch(epoch)
        {
            ByRangeRequestType::BlocksAndBlobs
        } else {
            ByRangeRequestType::Blocks
        }
    }

    pub fn insert_range_blocks_and_blobs_request(
        &mut self,
        id: Id,
        sender_id: RangeRequestId,
        info: RangeBlockComponentsRequest<T::EthSpec>,
    ) {
        self.range_block_components_requests
            .insert(id, (sender_id, info));
    }

    // Request handlers

    pub fn on_single_block_response(
        &mut self,
        request_id: SingleLookupReqId,
        peer_id: PeerId,
        rpc_event: RpcEvent<Arc<SignedBeaconBlock<T::EthSpec>>>,
    ) -> Option<RpcResponseResult<Arc<SignedBeaconBlock<T::EthSpec>>>> {
        let Entry::Occupied(mut request) = self.blocks_by_root_requests.entry(request_id) else {
            metrics::inc_counter_vec(&metrics::SYNC_UNKNOWN_NETWORK_REQUESTS, &["blocks_by_root"]);
            return None;
        };

        let resp = match rpc_event {
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
        rpc_event: RpcEvent<Arc<BlobSidecar<T::EthSpec>>>,
    ) -> Option<RpcResponseResult<FixedBlobSidecarList<T::EthSpec>>> {
        let Entry::Occupied(mut request) = self.blobs_by_root_requests.entry(request_id) else {
            metrics::inc_counter_vec(&metrics::SYNC_UNKNOWN_NETWORK_REQUESTS, &["blobs_by_root"]);
            return None;
        };

        let resp = match rpc_event {
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

    #[allow(clippy::type_complexity)]
    pub fn on_data_columns_by_root_response(
        &mut self,
        id: DataColumnsByRootRequestId,
        _peer_id: PeerId,
        rpc_event: RpcEvent<Arc<DataColumnSidecar<T::EthSpec>>>,
    ) -> Option<RpcResponseResult<Vec<Arc<DataColumnSidecar<T::EthSpec>>>>> {
        let Entry::Occupied(mut request) = self.data_columns_by_root_requests.entry(id) else {
            return None;
        };

        let resp = match rpc_event {
            RpcEvent::Response(data_column, seen_timestamp) => {
                let request = request.get_mut();
                match request.add_response(data_column) {
                    Ok(Some(data_columns)) => Ok((data_columns, seen_timestamp)),
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
            // catch if a peer is returning more columns than requested or if the excess blobs are
            // invalid.
            Err((e, resolved)) => {
                if let RpcResponseError::VerifyError(_e) = &e {
                    // TODO(das): this is a bug, we should not penalise peer in this case.
                    // confirm this can be removed.
                    // self.report_peer(peer_id, PeerAction::LowToleranceError, e.into());
                }
                if resolved {
                    None
                } else {
                    Some(Err(e))
                }
            }
        }
    }

    /// Insert a downloaded column into an active custody request. Then make progress on the
    /// entire request.
    ///
    /// ### Returns
    ///
    /// - `Some`: Request completed, won't make more progress. Expect requester to act on the result.
    /// - `None`: Request still active, requester should do no action
    #[allow(clippy::type_complexity)]
    pub fn on_custody_by_root_response(
        &mut self,
        id: CustodyId,
        req_id: DataColumnsByRootRequestId,
        peer_id: PeerId,
        resp: RpcResponseResult<Vec<Arc<DataColumnSidecar<T::EthSpec>>>>,
    ) -> Option<Result<(DataColumnSidecarList<T::EthSpec>, PeerGroup), RpcResponseError>> {
        // Note: need to remove the request to borrow self again below. Otherwise we can't
        // do nested requests
        let Some(mut request) = self.custody_by_root_requests.remove(&id.requester) else {
            // TOOD(das): This log can happen if the request is error'ed early and dropped
            debug!(self.log, "Custody column downloaded event for unknown request"; "id" => ?id);
            return None;
        };

        let result = request
            .on_data_column_downloaded(peer_id, req_id, resp, self)
            .map_err(RpcResponseError::CustodyRequestError)
            .transpose();

        // Convert a result from internal format of `ActiveCustodyRequest` (error first to use ?) to
        // an Option first to use in an `if let Some() { act on result }` block.
        if let Some(result) = result {
            match result.as_ref() {
                Ok((columns, peer_group)) => {
                    debug!(self.log, "Custody request success, removing"; "id" => ?id, "count" => columns.len(), "peers" => ?peer_group)
                }
                Err(e) => {
                    debug!(self.log, "Custody request failure, removing"; "id" => ?id, "error" => ?e)
                }
            }

            Some(result)
        } else {
            self.custody_by_root_requests.insert(id.requester, request);
            None
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

    pub fn send_custody_columns_for_processing(
        &self,
        _id: Id,
        block_root: Hash256,
        custody_columns: DataColumnSidecarList<T::EthSpec>,
        duration: Duration,
        process_type: BlockProcessType,
    ) -> Result<(), SendErrorProcessor> {
        let beacon_processor = self
            .beacon_processor_if_enabled()
            .ok_or(SendErrorProcessor::ProcessorNotAvailable)?;

        debug!(self.log, "Sending custody columns for processing"; "block" => ?block_root, "process_type" => ?process_type);

        beacon_processor
            .send_rpc_custody_columns(block_root, custody_columns, duration, process_type)
            .map_err(|e| {
                error!(
                    self.log,
                    "Failed to send sync custody columns to processor";
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
            self.range_block_components_requests.len() as i64,
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
            .ok_or(LookupVerifyError::UnrequestedIndex(index as u64))? = Some(blob)
    }
    Ok(fixed_list)
}
