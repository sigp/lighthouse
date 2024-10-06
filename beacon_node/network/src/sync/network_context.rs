//! Provides network functionality for the Syncing thread. This fundamentally wraps a network
//! channel and stores a global RPC ID to perform requests.

use self::custody::{ActiveCustodyRequest, Error as CustodyRequestError};
pub use self::requests::{BlocksByRootSingleRequest, DataColumnsByRootSingleBlockRequest};
use super::block_sidecar_coupling::RangeBlockComponentsRequest;
use super::manager::BlockProcessType;
use super::range_sync::ByRangeRequestType;
use crate::metrics;
use crate::network_beacon_processor::NetworkBeaconProcessor;
use crate::service::NetworkMessage;
use crate::status::ToStatusMessage;
use crate::sync::block_lookups::SingleLookupId;
use crate::sync::network_context::requests::BlobsByRootSingleBlockRequest;
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockProcessStatus, EngineState};
use custody::CustodyRequestResult;
use fnv::FnvHashMap;
use lighthouse_network::rpc::methods::{BlobsByRangeRequest, DataColumnsByRangeRequest};
use lighthouse_network::rpc::{BlocksByRangeRequest, GoodbyeReason, RPCError, RequestType};
pub use lighthouse_network::service::api_types::RangeRequestId;
use lighthouse_network::service::api_types::{
    AppRequestId, BlobsByRangeRequestId, BlocksByRangeRequestId, ComponentsByRangeRequestId,
    CustodyId, CustodyRequester, DataColumnsByRangeRequestId, DataColumnsByRootRequestId,
    DataColumnsByRootRequester, Id, SingleLookupReqId, SyncRequestId,
};
use lighthouse_network::{Client, NetworkGlobals, PeerAction, PeerId, ReportSource};
use rand::seq::SliceRandom;
use rand::thread_rng;
pub use requests::LookupVerifyError;
use requests::{
    ActiveRequests, BlobsByRangeRequestItems, BlobsByRootRequestItems, BlocksByRangeRequestItems,
    BlocksByRootRequestItems, DataColumnsByRangeRequestItems, DataColumnsByRootRequestItems,
};
use slog::{debug, error, warn};
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

#[derive(Debug)]
pub enum RpcEvent<T> {
    StreamTermination,
    Response(T, Duration),
    RPCError(RPCError),
}

impl<T> RpcEvent<T> {
    pub fn from_chunk(chunk: Option<T>, seen_timestamp: Duration) -> Self {
        match chunk {
            Some(item) => RpcEvent::Response(item, seen_timestamp),
            None => RpcEvent::StreamTermination,
        }
    }
}

pub type RpcResponseResult<T> = Result<(T, Duration), RpcResponseError>;

pub type CustodyByRootResult<T> = Result<(DataColumnSidecarList<T>, PeerGroup), RpcResponseError>;

#[derive(Debug)]
pub enum RpcResponseError {
    RpcError(RPCError),
    VerifyError(LookupVerifyError),
    CustodyRequestError(CustodyRequestError),
    BlockComponentCouplingError(String),
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
        // TODO: Review why this Display impl is necessary
        write!(f, "{:?}", self)
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
    pub fn of_index(&self, index: usize) -> impl Iterator<Item = &PeerId> + '_ {
        self.peers.iter().filter_map(move |(peer, indices)| {
            if indices.contains(&index) {
                Some(peer)
            } else {
                None
            }
        })
    }
}

/// Sequential ID that uniquely identifies ReqResp outgoing requests
pub type ReqId = u32;

pub enum LookupRequestResult<I = ReqId> {
    /// A request is sent. Sync MUST receive an event from the network in the future for either:
    /// completed response or failed request
    RequestSent(I),
    /// No request is sent, and no further action is necessary to consider this request completed.
    /// Includes a reason why this request is not needed.
    NoRequestNeeded(&'static str),
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
    blocks_by_root_requests:
        ActiveRequests<SingleLookupReqId, BlocksByRootRequestItems<T::EthSpec>>,
    /// A mapping of active BlobsByRoot requests, including both current slot and parent lookups.
    blobs_by_root_requests: ActiveRequests<SingleLookupReqId, BlobsByRootRequestItems<T::EthSpec>>,
    /// A mapping of active DataColumnsByRoot requests
    data_columns_by_root_requests:
        ActiveRequests<DataColumnsByRootRequestId, DataColumnsByRootRequestItems<T::EthSpec>>,
    /// A mapping of active BlocksByRange requests
    blocks_by_range_requests:
        ActiveRequests<BlocksByRangeRequestId, BlocksByRangeRequestItems<T::EthSpec>>,
    /// A mapping of active BlobsByRange requests
    blobs_by_range_requests:
        ActiveRequests<BlobsByRangeRequestId, BlobsByRangeRequestItems<T::EthSpec>>,
    /// A mapping of active DataColumnsByRange requests
    data_columns_by_range_requests:
        ActiveRequests<DataColumnsByRangeRequestId, DataColumnsByRangeRequestItems<T::EthSpec>>,

    /// Mapping of active custody column requests for a block root
    custody_by_root_requests: FnvHashMap<CustodyRequester, ActiveCustodyRequest<T>>,

    /// BlocksByRange requests paired with BlobsByRange
    components_by_range_requests:
        FnvHashMap<ComponentsByRangeRequestId, RangeBlockComponentsRequest<T::EthSpec>>,

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
    Block(RpcResponseResult<Vec<Arc<SignedBeaconBlock<E>>>>),
    Blob(RpcResponseResult<Vec<Arc<BlobSidecar<E>>>>),
    CustodyColumns(RpcResponseResult<Vec<Arc<DataColumnSidecar<E>>>>),
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
            blocks_by_root_requests: ActiveRequests::new("blocks_by_root"),
            blobs_by_root_requests: ActiveRequests::new("blobs_by_root"),
            data_columns_by_root_requests: ActiveRequests::new("data_columns_by_root"),
            blocks_by_range_requests: ActiveRequests::new("blocks_by_range"),
            blobs_by_range_requests: ActiveRequests::new("blobs_by_range"),
            data_columns_by_range_requests: ActiveRequests::new("data_columns_by_range"),
            custody_by_root_requests: <_>::default(),
            components_by_range_requests: FnvHashMap::default(),
            network_beacon_processor,
            chain,
            log,
        }
    }

    /// Returns the ids of all the requests made to the given peer_id.
    pub fn peer_disconnected(&mut self, peer_id: &PeerId) -> Vec<SyncRequestId> {
        // Note: using destructuring pattern without a default case to make sure we don't forget to
        // add new request types to the this function. Otherwise, lookup sync can break and lookups
        // will get stuck if a peer disconnects during an active requests.
        let Self {
            network_send: _,
            request_id: _,
            blocks_by_root_requests,
            blobs_by_root_requests,
            data_columns_by_root_requests,
            blocks_by_range_requests,
            blobs_by_range_requests,
            data_columns_by_range_requests,
            // custody_by_root_requests is a meta request of data_columns_by_root_requests
            custody_by_root_requests: _,
            // components_by_range_requests is a meta request of various _by_range requests
            components_by_range_requests: _,
            execution_engine_state: _,
            network_beacon_processor: _,
            chain: _,
            log: _,
        } = self;

        let blocks_by_root_ids = blocks_by_root_requests
            .active_requests_of_peer(peer_id)
            .into_iter()
            .map(|id| SyncRequestId::SingleBlock { id: *id });
        let blobs_by_root_ids = blobs_by_root_requests
            .active_requests_of_peer(peer_id)
            .into_iter()
            .map(|id| SyncRequestId::SingleBlob { id: *id });
        let data_column_by_root_ids = data_columns_by_root_requests
            .active_requests_of_peer(peer_id)
            .into_iter()
            .map(|req_id| SyncRequestId::DataColumnsByRoot(*req_id));
        let blocks_by_range_ids = blocks_by_range_requests
            .active_requests_of_peer(peer_id)
            .into_iter()
            .map(|req_id| SyncRequestId::BlocksByRange(*req_id));
        let blobs_by_range_ids = blobs_by_range_requests
            .active_requests_of_peer(peer_id)
            .into_iter()
            .map(|req_id| SyncRequestId::BlobsByRange(*req_id));
        let data_column_by_range_ids = data_columns_by_range_requests
            .active_requests_of_peer(peer_id)
            .into_iter()
            .map(|req_id| SyncRequestId::DataColumnsByRange(*req_id));

        blocks_by_root_ids
            .chain(blobs_by_root_ids)
            .chain(data_column_by_root_ids)
            .chain(blocks_by_range_ids)
            .chain(blobs_by_range_ids)
            .chain(data_column_by_range_ids)
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

            let request = RequestType::Status(status_message.clone());
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
        requester: RangeRequestId,
    ) -> Result<Id, RpcRequestSendError> {
        // Create the overall components_by_range request ID before its individual components
        let id = ComponentsByRangeRequestId {
            id: self.next_id(),
            requester,
        };

        let _blocks_req_id = self.send_blocks_by_range_request(peer_id, request.clone(), id)?;

        let blobs_req_id = if matches!(batch_type, ByRangeRequestType::BlocksAndBlobs) {
            Some(self.send_blobs_by_range_request(
                peer_id,
                BlobsByRangeRequest {
                    start_slot: *request.start_slot(),
                    count: *request.count(),
                },
                id,
            )?)
        } else {
            None
        };

        let (expects_columns, data_column_requests) =
            if matches!(batch_type, ByRangeRequestType::BlocksAndColumns) {
                let column_indexes = self.network_globals().sampling_columns.clone();

                let data_column_requests = self
                    .make_columns_by_range_requests(request, &column_indexes)?
                    .into_iter()
                    .map(|(peer_id, columns_by_range_request)| {
                        self.send_data_columns_by_range_request(
                            peer_id,
                            columns_by_range_request,
                            id,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                (Some(column_indexes), Some(data_column_requests))
            } else {
                (None, None)
            };

        let expected_blobs = blobs_req_id.is_some();
        let info = RangeBlockComponentsRequest::new(
            expected_blobs,
            expects_columns,
            data_column_requests.map(|items| items.len()),
        );
        self.components_by_range_requests.insert(id, info);

        Ok(id.id)
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

    /// Received a blocks by range or blobs by range response for a request that couples blocks '
    /// and blobs.
    pub fn range_block_and_blob_response(
        &mut self,
        id: ComponentsByRangeRequestId,
        block_or_blob: BlockOrBlob<T::EthSpec>,
    ) -> Option<Result<Vec<RpcBlock<T::EthSpec>>, RpcResponseError>> {
        let Entry::Occupied(mut entry) = self.components_by_range_requests.entry(id) else {
            metrics::inc_counter_vec(&metrics::SYNC_UNKNOWN_NETWORK_REQUESTS, &["range_blocks"]);
            return None;
        };

        if let Err(e) = {
            let request = entry.get_mut();
            match block_or_blob {
                BlockOrBlob::Block(resp) => match resp {
                    Ok((blocks, _)) => Ok(request.add_blocks(blocks)),
                    Err(e) => Err(e),
                },
                BlockOrBlob::Blob(resp) => match resp {
                    Ok((blobs, _)) => Ok(request.add_blobs(blobs)),
                    Err(e) => Err(e),
                },
                BlockOrBlob::CustodyColumns(resp) => match resp {
                    Ok((custody_columns, _)) => Ok(request.add_custody_columns(custody_columns)),
                    Err(e) => Err(e),
                },
            }
        } {
            entry.remove();
            return Some(Err(e));
        }

        if entry.get_mut().is_finished() {
            // If the request is finished, dequeue everything
            let request = entry.remove();
            let blocks = request
                .into_responses(&self.chain.spec)
                .map_err(RpcResponseError::BlockComponentCouplingError);
            Some(blocks)
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
                return Ok(LookupRequestResult::NoRequestNeeded(
                    "block execution validated",
                ))
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
                request: RequestType::BlocksByRoot(request.into_request(&self.chain.spec)),
                request_id: AppRequestId::Sync(SyncRequestId::SingleBlock { id }),
            })
            .map_err(|_| RpcRequestSendError::NetworkSendError)?;

        self.blocks_by_root_requests.insert(
            id,
            peer_id,
            // true = enforce max_requests as returned for blocks_by_root. We always request a single
            // block and the peer must have it.
            true,
            BlocksByRootRequestItems::new(request),
        );

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
            // In case (2) the block will be downloaded, processed, reach `DuplicateFullyImported`
            // and get dropped as completed.
            return Ok(LookupRequestResult::Pending("waiting for block download"));
        };
        let expected_blobs = block.num_expected_blobs();
        let block_epoch = block.slot().epoch(T::EthSpec::slots_per_epoch());

        // Check if we are in deneb, before peerdas and inside da window
        if !self.chain.should_fetch_blobs(block_epoch) {
            return Ok(LookupRequestResult::NoRequestNeeded("blobs not required"));
        }

        // No data required for this block
        if expected_blobs == 0 {
            return Ok(LookupRequestResult::NoRequestNeeded("no data"));
        }

        let imported_blob_indexes = self
            .chain
            .data_availability_checker
            .cached_blob_indexes(&block_root)
            .unwrap_or_default();
        // Include only the blob indexes not yet imported (received through gossip)
        let indices = (0..expected_blobs as u64)
            .filter(|index| !imported_blob_indexes.contains(index))
            .collect::<Vec<_>>();

        if indices.is_empty() {
            // No blobs required, do not issue any request
            return Ok(LookupRequestResult::NoRequestNeeded("no indices to fetch"));
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
                request: RequestType::BlobsByRoot(request.clone().into_request(&self.chain.spec)),
                request_id: AppRequestId::Sync(SyncRequestId::SingleBlob { id }),
            })
            .map_err(|_| RpcRequestSendError::NetworkSendError)?;

        self.blobs_by_root_requests.insert(
            id,
            peer_id,
            // true = enforce max_requests are returned for blobs_by_root. We only issue requests for
            // blocks after we know the block has data, and only request peers after they claim to
            // have imported the block+blobs.
            true,
            BlobsByRootRequestItems::new(request),
        );

        Ok(LookupRequestResult::RequestSent(req_id))
    }

    /// Request to send a single `data_columns_by_root` request to the network.
    pub fn data_column_lookup_request(
        &mut self,
        requester: DataColumnsByRootRequester,
        peer_id: PeerId,
        request: DataColumnsByRootSingleBlockRequest,
        expect_max_responses: bool,
    ) -> Result<LookupRequestResult<DataColumnsByRootRequestId>, &'static str> {
        let req_id = DataColumnsByRootRequestId {
            id: self.next_id(),
            requester,
        };
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
            request: RequestType::DataColumnsByRoot(request.clone().into_request(&self.chain.spec)),
            request_id: AppRequestId::Sync(SyncRequestId::DataColumnsByRoot(req_id)),
        })?;

        self.data_columns_by_root_requests.insert(
            req_id,
            peer_id,
            expect_max_responses,
            DataColumnsByRootRequestItems::new(request),
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

        // Check if we are into peerdas and inside da window
        if !self.chain.should_fetch_custody_columns(block_epoch) {
            return Ok(LookupRequestResult::NoRequestNeeded("columns not required"));
        }

        // No data required for this block
        if expected_blobs == 0 {
            return Ok(LookupRequestResult::NoRequestNeeded("no data"));
        }

        let custody_indexes_imported = self
            .chain
            .data_availability_checker
            .cached_data_column_indexes(&block_root)
            .unwrap_or_default();

        // Include only the blob indexes not yet imported (received through gossip)
        let custody_indexes_to_fetch = self
            .network_globals()
            .sampling_columns
            .clone()
            .into_iter()
            .filter(|index| !custody_indexes_imported.contains(index))
            .collect::<Vec<_>>();

        if custody_indexes_to_fetch.is_empty() {
            // No indexes required, do not issue any request
            return Ok(LookupRequestResult::NoRequestNeeded("no indices to fetch"));
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

    fn send_blocks_by_range_request(
        &mut self,
        peer_id: PeerId,
        request: BlocksByRangeRequest,
        requester: ComponentsByRangeRequestId,
    ) -> Result<BlocksByRangeRequestId, RpcRequestSendError> {
        let id = BlocksByRangeRequestId {
            id: self.next_id(),
            requester,
        };
        debug!(
            self.log,
            "Sending BlocksByRange request";
            "method" => "BlocksByRange",
            "count" => request.count(),
            "epoch" => Slot::new(*request.start_slot()).epoch(T::EthSpec::slots_per_epoch()),
            "peer" => %peer_id,
            "id" => ?id,
        );
        self.network_send
            .send(NetworkMessage::SendRequest {
                peer_id,
                request: RequestType::BlocksByRange(request.clone().into()),
                request_id: AppRequestId::Sync(SyncRequestId::BlocksByRange(id)),
            })
            .map_err(|_| RpcRequestSendError::NetworkSendError)?;

        self.blocks_by_range_requests.insert(
            id,
            peer_id,
            // false = do not enforce max_requests are returned for *_by_range methods. We don't
            // know if there are missed blocks.
            false,
            BlocksByRangeRequestItems::new(request),
        );
        Ok(id)
    }

    fn send_blobs_by_range_request(
        &mut self,
        peer_id: PeerId,
        request: BlobsByRangeRequest,
        requester: ComponentsByRangeRequestId,
    ) -> Result<BlobsByRangeRequestId, RpcRequestSendError> {
        let id = BlobsByRangeRequestId {
            id: self.next_id(),
            requester,
        };
        debug!(
            self.log,
            "Sending BlobsByRange requests";
            "method" => "BlobsByRange",
            "count" => request.count,
            "epoch" => Slot::new(request.start_slot).epoch(T::EthSpec::slots_per_epoch()),
            "peer" => %peer_id,
            "id" => ?id,
        );

        // Create the blob request based on the blocks request.
        self.network_send
            .send(NetworkMessage::SendRequest {
                peer_id,
                request: RequestType::BlobsByRange(request.clone()),
                request_id: AppRequestId::Sync(SyncRequestId::BlobsByRange(id)),
            })
            .map_err(|_| RpcRequestSendError::NetworkSendError)?;

        self.blobs_by_range_requests.insert(
            id,
            peer_id,
            // false = do not enforce max_requests are returned for *_by_range methods. We don't
            // know if there are missed blocks.
            false,
            BlobsByRangeRequestItems::new(request),
        );
        Ok(id)
    }

    fn send_data_columns_by_range_request(
        &mut self,
        peer_id: PeerId,
        request: DataColumnsByRangeRequest,
        requester: ComponentsByRangeRequestId,
    ) -> Result<DataColumnsByRangeRequestId, RpcRequestSendError> {
        let id = DataColumnsByRangeRequestId {
            id: self.next_id(),
            requester,
        };
        debug!(
            self.log,
            "Sending DataColumnsByRange requests";
            "method" => "DataColumnsByRange",
            "count" => request.count,
            "epoch" => Slot::new(request.start_slot).epoch(T::EthSpec::slots_per_epoch()),
            "columns" => ?request.columns,
            "peer" => %peer_id,
            "id" => ?id,
        );

        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request: RequestType::DataColumnsByRange(request.clone()),
            request_id: AppRequestId::Sync(SyncRequestId::DataColumnsByRange(id)),
        })
        .map_err(|_| RpcRequestSendError::NetworkSendError)?;

        self.data_columns_by_range_requests.insert(
            id,
            peer_id,
            // false = do not enforce max_requests are returned for *_by_range methods. We don't
            // know if there are missed blocks.
            false,
            DataColumnsByRangeRequestItems::new(request),
        );
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

    /// Attempt to make progress on all custody_by_root requests. Some request may be stale waiting
    /// for custody peers. Returns a Vec of results as zero or more requests may fail in this
    /// attempt.
    pub fn continue_custody_by_root_requests(
        &mut self,
    ) -> Vec<(CustodyRequester, CustodyByRootResult<T::EthSpec>)> {
        let ids = self
            .custody_by_root_requests
            .keys()
            .copied()
            .collect::<Vec<_>>();

        // Need to collect ids and results in separate steps to re-borrow self.
        ids.into_iter()
            .filter_map(|id| {
                let mut request = self
                    .custody_by_root_requests
                    .remove(&id)
                    .expect("key of hashmap");
                let result = request.continue_requests(self);
                self.handle_custody_by_root_result(id, request, result)
                    .map(|result| (id, result))
            })
            .collect()
    }

    // Request handlers

    pub(crate) fn on_single_block_response(
        &mut self,
        id: SingleLookupReqId,
        peer_id: PeerId,
        rpc_event: RpcEvent<Arc<SignedBeaconBlock<T::EthSpec>>>,
    ) -> Option<RpcResponseResult<Arc<SignedBeaconBlock<T::EthSpec>>>> {
        let response = self.blocks_by_root_requests.on_response(id, rpc_event);
        let response = response.map(|res| {
            res.and_then(|(mut blocks, seen_timestamp)| {
                // Enforce that exactly one chunk = one block is returned. ReqResp behavior limits the
                // response count to at most 1.
                match blocks.pop() {
                    Some(block) => Ok((block, seen_timestamp)),
                    // Should never happen, `blocks_by_root_requests` enforces that we receive at least
                    // 1 chunk.
                    None => Err(LookupVerifyError::NotEnoughResponsesReturned { actual: 0 }.into()),
                }
            })
        });
        if let Some(Err(RpcResponseError::VerifyError(e))) = &response {
            self.report_peer(peer_id, PeerAction::LowToleranceError, e.into());
        }
        response
    }

    pub(crate) fn on_single_blob_response(
        &mut self,
        id: SingleLookupReqId,
        peer_id: PeerId,
        rpc_event: RpcEvent<Arc<BlobSidecar<T::EthSpec>>>,
    ) -> Option<RpcResponseResult<FixedBlobSidecarList<T::EthSpec>>> {
        let response = self.blobs_by_root_requests.on_response(id, rpc_event);
        let response = response.map(|res| {
            res.and_then(
                |(blobs, seen_timestamp)| match to_fixed_blob_sidecar_list(blobs) {
                    Ok(blobs) => Ok((blobs, seen_timestamp)),
                    Err(e) => Err(e.into()),
                },
            )
        });
        if let Some(Err(RpcResponseError::VerifyError(e))) = &response {
            self.report_peer(peer_id, PeerAction::LowToleranceError, e.into());
        }
        response
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn on_data_columns_by_root_response(
        &mut self,
        id: DataColumnsByRootRequestId,
        peer_id: PeerId,
        rpc_event: RpcEvent<Arc<DataColumnSidecar<T::EthSpec>>>,
    ) -> Option<RpcResponseResult<Vec<Arc<DataColumnSidecar<T::EthSpec>>>>> {
        let resp = self
            .data_columns_by_root_requests
            .on_response(id, rpc_event);
        self.report_rpc_response_errors(resp, peer_id)
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn on_blocks_by_range_response(
        &mut self,
        id: BlocksByRangeRequestId,
        peer_id: PeerId,
        rpc_event: RpcEvent<Arc<SignedBeaconBlock<T::EthSpec>>>,
    ) -> Option<RpcResponseResult<Vec<Arc<SignedBeaconBlock<T::EthSpec>>>>> {
        let resp = self.blocks_by_range_requests.on_response(id, rpc_event);
        self.report_rpc_response_errors(resp, peer_id)
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn on_blobs_by_range_response(
        &mut self,
        id: BlobsByRangeRequestId,
        peer_id: PeerId,
        rpc_event: RpcEvent<Arc<BlobSidecar<T::EthSpec>>>,
    ) -> Option<RpcResponseResult<Vec<Arc<BlobSidecar<T::EthSpec>>>>> {
        let resp = self.blobs_by_range_requests.on_response(id, rpc_event);
        self.report_rpc_response_errors(resp, peer_id)
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn on_data_columns_by_range_response(
        &mut self,
        id: DataColumnsByRangeRequestId,
        peer_id: PeerId,
        rpc_event: RpcEvent<Arc<DataColumnSidecar<T::EthSpec>>>,
    ) -> Option<RpcResponseResult<Vec<Arc<DataColumnSidecar<T::EthSpec>>>>> {
        let resp = self
            .data_columns_by_range_requests
            .on_response(id, rpc_event);
        self.report_rpc_response_errors(resp, peer_id)
    }

    fn report_rpc_response_errors<R>(
        &mut self,
        resp: Option<RpcResponseResult<R>>,
        peer_id: PeerId,
    ) -> Option<RpcResponseResult<R>> {
        if let Some(Err(RpcResponseError::VerifyError(e))) = &resp {
            self.report_peer(peer_id, PeerAction::LowToleranceError, e.into());
        }
        resp
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
    ) -> Option<CustodyByRootResult<T::EthSpec>> {
        // Note: need to remove the request to borrow self again below. Otherwise we can't
        // do nested requests
        let Some(mut request) = self.custody_by_root_requests.remove(&id.requester) else {
            // TOOD(das): This log can happen if the request is error'ed early and dropped
            debug!(self.log, "Custody column downloaded event for unknown request"; "id" => ?id);
            return None;
        };

        let result = request.on_data_column_downloaded(peer_id, req_id, resp, self);

        self.handle_custody_by_root_result(id.requester, request, result)
    }

    fn handle_custody_by_root_result(
        &mut self,
        id: CustodyRequester,
        request: ActiveCustodyRequest<T>,
        result: CustodyRequestResult<T::EthSpec>,
    ) -> Option<CustodyByRootResult<T::EthSpec>> {
        let result = result
            .map_err(RpcResponseError::CustodyRequestError)
            .transpose();

        // Convert a result from internal format of `ActiveCustodyRequest` (error first to use ?) to
        // an Option first to use in an `if let Some() { act on result }` block.
        match result.as_ref() {
            Some(Ok((columns, peer_group))) => {
                debug!(self.log, "Custody request success, removing"; "id" => ?id, "count" => columns.len(), "peers" => ?peer_group)
            }
            Some(Err(e)) => {
                debug!(self.log, "Custody request failure, removing"; "id" => ?id, "error" => ?e)
            }
            None => {
                self.custody_by_root_requests.insert(id, request);
            }
        }
        result
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
        for (id, count) in [
            ("blocks_by_root", self.blocks_by_root_requests.len()),
            ("blobs_by_root", self.blobs_by_root_requests.len()),
            ("data_columns_by_root", self.blocks_by_root_requests.len()),
            ("blocks_by_range", self.blocks_by_range_requests.len()),
            ("blobs_by_range", self.blobs_by_range_requests.len()),
            ("data_columns_by_range", self.blocks_by_range_requests.len()),
            ("custody_by_root", self.custody_by_root_requests.len()),
            (
                "components_by_range",
                self.components_by_range_requests.len(),
            ),
        ] {
            metrics::set_gauge_vec(&metrics::SYNC_ACTIVE_NETWORK_REQUESTS, &[id], count as i64);
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
            .ok_or(LookupVerifyError::UnrequestedIndex(index as u64))? = Some(blob)
    }
    Ok(fixed_list)
}
