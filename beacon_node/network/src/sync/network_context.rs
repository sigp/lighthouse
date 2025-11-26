//! Provides network functionality for the Syncing thread. This fundamentally wraps a network
//! channel and stores a global RPC ID to perform requests.

use self::custody::{ActiveCustodyRequest, Error as CustodyRequestError};
pub use self::requests::{BlocksByRootSingleRequest, DataColumnsByRootSingleBlockRequest};
use super::SyncMessage;
use super::block_sidecar_coupling::RangeBlockComponentsRequest;
use super::manager::BlockProcessType;
use crate::metrics;
use crate::network_beacon_processor::NetworkBeaconProcessor;
#[cfg(test)]
use crate::network_beacon_processor::TestBeaconChainType;
use crate::service::NetworkMessage;
use crate::status::ToStatusMessage;
use crate::sync::batch::ByRangeRequestType;
use crate::sync::block_lookups::SingleLookupId;
use crate::sync::block_sidecar_coupling::CouplingError;
use crate::sync::network_context::requests::BlobsByRootSingleBlockRequest;
use crate::sync::range_data_column_batch_request::RangeDataColumnBatchRequest;
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockProcessStatus, EngineState};
use custody::CustodyRequestResult;
use fnv::FnvHashMap;
use lighthouse_network::rpc::methods::{BlobsByRangeRequest, DataColumnsByRangeRequest};
use lighthouse_network::rpc::{BlocksByRangeRequest, GoodbyeReason, RPCError, RequestType};
pub use lighthouse_network::service::api_types::RangeRequestId;
use lighthouse_network::service::api_types::{
    AppRequestId, BlobsByRangeRequestId, BlocksByRangeRequestId, ComponentsByRangeRequestId,
    CustodyBackFillBatchRequestId, CustodyBackfillBatchId, CustodyId, CustodyRequester,
    DataColumnsByRangeRequestId, DataColumnsByRangeRequester, DataColumnsByRootRequestId,
    DataColumnsByRootRequester, Id, SingleLookupReqId, SyncRequestId,
};
use lighthouse_network::{Client, NetworkGlobals, PeerAction, PeerId, ReportSource};
use lighthouse_tracing::{SPAN_OUTGOING_BLOCK_BY_ROOT_REQUEST, SPAN_OUTGOING_RANGE_REQUEST};
use parking_lot::RwLock;
pub use requests::LookupVerifyError;
use requests::{
    ActiveRequests, BlobsByRangeRequestItems, BlobsByRootRequestItems, BlocksByRangeRequestItems,
    BlocksByRootRequestItems, DataColumnsByRangeRequestItems, DataColumnsByRootRequestItems,
};
#[cfg(test)]
use slot_clock::SlotClock;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;
#[cfg(test)]
use task_executor::TaskExecutor;
use tokio::sync::mpsc;
use tracing::{Span, debug, debug_span, error, warn};
use types::blob_sidecar::FixedBlobSidecarList;
use types::{
    BlobSidecar, BlockImportSource, ColumnIndex, DataColumnSidecar, DataColumnSidecarList, EthSpec,
    ForkContext, Hash256, SignedBeaconBlock, Slot,
};

pub mod custody;
mod requests;

macro_rules! new_range_request_span {
    ($self:expr, $name:literal, $parent:expr, $peer_id:expr) => {{
        let client = $self.client_type(&$peer_id).kind;
        debug_span!(
            parent: $parent,
            $name,
            peer_id = %$peer_id,
            client = %client
        )
    }};
}

/// Max retries for block components after which we fail the batch.
pub const MAX_COLUMN_RETRIES: usize = 3;

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

/// Duration = latest seen timestamp of all received data columns
pub type CustodyByRootResult<T> =
    Result<(DataColumnSidecarList<T>, PeerGroup, Duration), RpcResponseError>;

#[derive(Debug)]
pub enum RpcResponseError {
    RpcError(#[allow(dead_code)] RPCError),
    VerifyError(LookupVerifyError),
    CustodyRequestError(#[allow(dead_code)] CustodyRequestError),
    BlockComponentCouplingError(CouplingError),
}

#[derive(Debug, PartialEq, Eq)]
pub enum RpcRequestSendError {
    /// No peer available matching the required criteria
    NoPeer(NoPeerError),
    /// These errors should never happen, including unreachable custody errors or network send
    /// errors.
    InternalError(String),
}

/// Type of peer missing that caused a `RpcRequestSendError::NoPeers`
#[derive(Debug, PartialEq, Eq)]
pub enum NoPeerError {
    BlockPeer,
    CustodyPeer(ColumnIndex),
}

#[derive(Debug, PartialEq, Eq)]
pub enum SendErrorProcessor {
    SendError,
    ProcessorNotAvailable,
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

    /// BlocksByRange requests paired with other ByRange requests for data components
    components_by_range_requests:
        FnvHashMap<ComponentsByRangeRequestId, RangeBlockComponentsRequest<T::EthSpec>>,

    /// A batch of data columns by range request for custody sync
    custody_backfill_data_column_batch_requests:
        FnvHashMap<CustodyBackFillBatchRequestId, RangeDataColumnBatchRequest<T>>,

    /// Whether the ee is online. If it's not, we don't allow access to the
    /// `beacon_processor_send`.
    execution_engine_state: EngineState,

    /// Sends work to the beacon processor via a channel.
    network_beacon_processor: Arc<NetworkBeaconProcessor<T>>,

    pub chain: Arc<BeaconChain<T>>,

    fork_context: Arc<ForkContext>,
}

/// Small enumeration to make dealing with block and blob requests easier.
pub enum RangeBlockComponent<E: EthSpec> {
    Block(
        BlocksByRangeRequestId,
        RpcResponseResult<Vec<Arc<SignedBeaconBlock<E>>>>,
    ),
    Blob(
        BlobsByRangeRequestId,
        RpcResponseResult<Vec<Arc<BlobSidecar<E>>>>,
    ),
    CustodyColumns(
        DataColumnsByRangeRequestId,
        RpcResponseResult<Vec<Arc<DataColumnSidecar<E>>>>,
    ),
}

#[cfg(test)]
impl<E: EthSpec> SyncNetworkContext<TestBeaconChainType<E>> {
    pub fn new_for_testing(
        beacon_chain: Arc<BeaconChain<TestBeaconChainType<E>>>,
        network_globals: Arc<NetworkGlobals<E>>,
        task_executor: TaskExecutor,
    ) -> Self {
        let fork_context = Arc::new(ForkContext::new::<E>(
            beacon_chain.slot_clock.now().unwrap_or(Slot::new(0)),
            beacon_chain.genesis_validators_root,
            &beacon_chain.spec,
        ));
        let (network_tx, _network_rx) = mpsc::unbounded_channel();
        let (beacon_processor, _) = NetworkBeaconProcessor::null_for_testing(
            network_globals,
            mpsc::unbounded_channel().0,
            beacon_chain.clone(),
            task_executor,
        );

        SyncNetworkContext::new(
            network_tx,
            Arc::new(beacon_processor),
            beacon_chain,
            fork_context,
        )
    }
}

impl<T: BeaconChainTypes> SyncNetworkContext<T> {
    pub fn new(
        network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
        network_beacon_processor: Arc<NetworkBeaconProcessor<T>>,
        chain: Arc<BeaconChain<T>>,
        fork_context: Arc<ForkContext>,
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
            custody_backfill_data_column_batch_requests: FnvHashMap::default(),
            network_beacon_processor,
            chain,
            fork_context,
        }
    }

    pub fn send_sync_message(&mut self, sync_message: SyncMessage<T::EthSpec>) {
        self.network_beacon_processor
            .send_sync_message(sync_message);
    }

    /// Returns the ids of all the requests made to the given peer_id.
    pub fn peer_disconnected(&mut self, peer_id: &PeerId) -> Vec<SyncRequestId> {
        // Note: using destructuring pattern without a default case to make sure we don't forget to
        // add new request types to this function. Otherwise, lookup sync can break and lookups
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
            custody_backfill_data_column_batch_requests: _,
            execution_engine_state: _,
            network_beacon_processor: _,
            chain: _,
            fork_context: _,
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
                peer = %peer_id,
                fork_digest = ?status_message.fork_digest(),
                finalized_root = ?status_message.finalized_root(),
                finalized_epoch = ?status_message.finalized_epoch(),
                head_root = %status_message.head_root(),
                head_slot = %status_message.head_slot(),
                earliest_available_slot = ?status_message.earliest_available_slot(),
                "Sending Status Request"
            );

            let request = RequestType::Status(status_message.clone());
            let app_request_id = AppRequestId::Router;
            let _ = self.send_network_msg(NetworkMessage::SendRequest {
                peer_id,
                request,
                app_request_id,
            });
        }
    }

    fn active_request_count_by_peer(&self) -> HashMap<PeerId, usize> {
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
            custody_backfill_data_column_batch_requests: _,
            execution_engine_state: _,
            network_beacon_processor: _,
            chain: _,
            fork_context: _,
            // Don't use a fallback match. We want to be sure that all requests are considered when
            // adding new ones
        } = self;

        let mut active_request_count_by_peer = HashMap::<PeerId, usize>::new();

        for peer_id in blocks_by_root_requests
            .iter_request_peers()
            .chain(blobs_by_root_requests.iter_request_peers())
            .chain(data_columns_by_root_requests.iter_request_peers())
            .chain(blocks_by_range_requests.iter_request_peers())
            .chain(blobs_by_range_requests.iter_request_peers())
            .chain(data_columns_by_range_requests.iter_request_peers())
        {
            *active_request_count_by_peer.entry(peer_id).or_default() += 1;
        }

        active_request_count_by_peer
    }

    /// Retries only the specified failed columns by requesting them again.
    ///
    /// Note: This function doesn't retry the whole batch, but retries specific requests within
    /// the batch.
    pub fn retry_columns_by_range(
        &mut self,
        id: Id,
        peers: &HashSet<PeerId>,
        peers_to_deprioritize: &HashSet<PeerId>,
        request: BlocksByRangeRequest,
        failed_columns: &HashSet<ColumnIndex>,
    ) -> Result<(), String> {
        let Some((requester, parent_request_span)) = self
            .components_by_range_requests
            .iter()
            .find_map(|(key, value)| {
                if key.id == id {
                    Some((key.requester, value.request_span.clone()))
                } else {
                    None
                }
            })
        else {
            return Err("request id not present".to_string());
        };

        let active_request_count_by_peer = self.active_request_count_by_peer();

        debug!(
            ?failed_columns,
            ?id,
            ?requester,
            "Retrying only failed column requests from other peers"
        );

        // Attempt to find all required custody peers to request the failed columns from
        let columns_by_range_peers_to_request = self
            .select_columns_by_range_peers_to_request(
                failed_columns,
                peers,
                active_request_count_by_peer,
                peers_to_deprioritize,
            )
            .map_err(|e| format!("{:?}", e))?;

        // Reuse the id for the request that received partially correct responses
        let id = ComponentsByRangeRequestId { id, requester };

        let data_column_requests = columns_by_range_peers_to_request
            .into_iter()
            .map(|(peer_id, columns)| {
                self.send_data_columns_by_range_request(
                    peer_id,
                    DataColumnsByRangeRequest {
                        start_slot: *request.start_slot(),
                        count: *request.count(),
                        columns,
                    },
                    DataColumnsByRangeRequester::ComponentsByRange(id),
                    new_range_request_span!(
                        self,
                        "outgoing_columns_by_range_retry",
                        parent_request_span.clone(),
                        peer_id
                    ),
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("{:?}", e))?;

        // instead of creating a new `RangeBlockComponentsRequest`, we reinsert
        // the new requests created for the failed requests
        let Some(range_request) = self.components_by_range_requests.get_mut(&id) else {
            return Err(
                "retrying custody request for range request that does not exist".to_string(),
            );
        };

        range_request.reinsert_failed_column_requests(data_column_requests)?;
        Ok(())
    }

    /// A blocks by range request sent by the range sync algorithm
    pub fn block_components_by_range_request(
        &mut self,
        batch_type: ByRangeRequestType,
        request: BlocksByRangeRequest,
        requester: RangeRequestId,
        block_peers: &HashSet<PeerId>,
        column_peers: &HashSet<PeerId>,
        peers_to_deprioritize: &HashSet<PeerId>,
    ) -> Result<Id, RpcRequestSendError> {
        let range_request_span = debug_span!(
            parent: None,
            SPAN_OUTGOING_RANGE_REQUEST,
            range_req_id = %requester,
            block_peers = block_peers.len(),
            column_peers = column_peers.len()
        );
        let _guard = range_request_span.clone().entered();
        let active_request_count_by_peer = self.active_request_count_by_peer();

        let Some(block_peer) = block_peers
            .iter()
            .map(|peer| {
                (
                    // If contains -> 1 (order after), not contains -> 0 (order first)
                    peers_to_deprioritize.contains(peer),
                    // Prefer peers with less overall requests
                    active_request_count_by_peer.get(peer).copied().unwrap_or(0),
                    // Random factor to break ties, otherwise the PeerID breaks ties
                    rand::random::<u32>(),
                    peer,
                )
            })
            .min()
            .map(|(_, _, _, peer)| *peer)
        else {
            // Backfill and forward sync handle this condition gracefully.
            // - Backfill sync: will pause waiting for more peers to join
            // - Forward sync: can never happen as the chain is dropped when removing the last peer.
            return Err(RpcRequestSendError::NoPeer(NoPeerError::BlockPeer));
        };

        // Attempt to find all required custody peers before sending any request or creating an ID
        let columns_by_range_peers_to_request =
            if matches!(batch_type, ByRangeRequestType::BlocksAndColumns) {
                let epoch = Slot::new(*request.start_slot()).epoch(T::EthSpec::slots_per_epoch());
                let column_indexes = self
                    .chain
                    .sampling_columns_for_epoch(epoch)
                    .iter()
                    .cloned()
                    .collect();
                Some(self.select_columns_by_range_peers_to_request(
                    &column_indexes,
                    column_peers,
                    active_request_count_by_peer,
                    peers_to_deprioritize,
                )?)
            } else {
                None
            };

        // Create the overall components_by_range request ID before its individual components
        let id = ComponentsByRangeRequestId {
            id: self.next_id(),
            requester,
        };

        let blocks_req_id = self.send_blocks_by_range_request(
            block_peer,
            request.clone(),
            id,
            new_range_request_span!(
                self,
                "outgoing_blocks_by_range",
                range_request_span.clone(),
                block_peer
            ),
        )?;

        let blobs_req_id = if matches!(batch_type, ByRangeRequestType::BlocksAndBlobs) {
            Some(self.send_blobs_by_range_request(
                block_peer,
                BlobsByRangeRequest {
                    start_slot: *request.start_slot(),
                    count: *request.count(),
                },
                id,
                new_range_request_span!(
                    self,
                    "outgoing_blobs_by_range",
                    range_request_span.clone(),
                    block_peer
                ),
            )?)
        } else {
            None
        };

        let data_column_requests = columns_by_range_peers_to_request
            .map(|columns_by_range_peers_to_request| {
                columns_by_range_peers_to_request
                    .into_iter()
                    .map(|(peer_id, columns)| {
                        self.send_data_columns_by_range_request(
                            peer_id,
                            DataColumnsByRangeRequest {
                                start_slot: *request.start_slot(),
                                count: *request.count(),
                                columns,
                            },
                            DataColumnsByRangeRequester::ComponentsByRange(id),
                            new_range_request_span!(
                                self,
                                "outgoing_columns_by_range",
                                range_request_span.clone(),
                                peer_id
                            ),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;

        let epoch = Slot::new(*request.start_slot()).epoch(T::EthSpec::slots_per_epoch());
        let info = RangeBlockComponentsRequest::new(
            blocks_req_id,
            blobs_req_id,
            data_column_requests.map(|data_column_requests| {
                (
                    data_column_requests,
                    self.chain.sampling_columns_for_epoch(epoch).to_vec(),
                )
            }),
            range_request_span,
        );
        self.components_by_range_requests.insert(id, info);

        Ok(id.id)
    }

    fn select_columns_by_range_peers_to_request(
        &self,
        custody_indexes: &HashSet<ColumnIndex>,
        peers: &HashSet<PeerId>,
        active_request_count_by_peer: HashMap<PeerId, usize>,
        peers_to_deprioritize: &HashSet<PeerId>,
    ) -> Result<HashMap<PeerId, Vec<ColumnIndex>>, RpcRequestSendError> {
        let mut columns_to_request_by_peer = HashMap::<PeerId, Vec<ColumnIndex>>::new();

        for column_index in custody_indexes {
            // Strictly consider peers that are custodials of this column AND are part of this
            // syncing chain. If the forward range sync chain has few peers, it's likely that this
            // function will not be able to find peers on our custody columns.
            let Some(custody_peer) = peers
                .iter()
                .filter(|peer| {
                    self.network_globals()
                        .is_custody_peer_of(*column_index, peer)
                })
                .map(|peer| {
                    (
                        // If contains -> 1 (order after), not contains -> 0 (order first)
                        peers_to_deprioritize.contains(peer),
                        // Prefer peers with less overall requests
                        // Also account for requests that are not yet issued tracked in peer_id_to_request_map
                        // We batch requests to the same peer, so count existance in the
                        // `columns_to_request_by_peer` as a single 1 request.
                        active_request_count_by_peer.get(peer).copied().unwrap_or(0)
                            + columns_to_request_by_peer.get(peer).map(|_| 1).unwrap_or(0),
                        // Random factor to break ties, otherwise the PeerID breaks ties
                        rand::random::<u32>(),
                        peer,
                    )
                })
                .min()
                .map(|(_, _, _, peer)| *peer)
            else {
                // TODO(das): this will be pretty bad UX. To improve we should:
                // - Handle the no peers case gracefully, maybe add some timeout and give a few
                //   minutes / seconds to the peer manager to locate peers on this subnet before
                //   abandoing progress on the chain completely.
                return Err(RpcRequestSendError::NoPeer(NoPeerError::CustodyPeer(
                    *column_index,
                )));
            };

            columns_to_request_by_peer
                .entry(custody_peer)
                .or_default()
                .push(*column_index);
        }

        Ok(columns_to_request_by_peer)
    }

    /// Received a blocks by range or blobs by range response for a request that couples blocks '
    /// and blobs.
    pub fn range_block_component_response(
        &mut self,
        id: ComponentsByRangeRequestId,
        range_block_component: RangeBlockComponent<T::EthSpec>,
    ) -> Option<Result<Vec<RpcBlock<T::EthSpec>>, RpcResponseError>> {
        let Entry::Occupied(mut entry) = self.components_by_range_requests.entry(id) else {
            metrics::inc_counter_vec(&metrics::SYNC_UNKNOWN_NETWORK_REQUESTS, &["range_blocks"]);
            return None;
        };

        if let Err(e) = {
            let request = entry.get_mut();
            match range_block_component {
                RangeBlockComponent::Block(req_id, resp) => resp.and_then(|(blocks, _)| {
                    request.add_blocks(req_id, blocks).map_err(|e| {
                        RpcResponseError::BlockComponentCouplingError(CouplingError::InternalError(
                            e,
                        ))
                    })
                }),
                RangeBlockComponent::Blob(req_id, resp) => resp.and_then(|(blobs, _)| {
                    request.add_blobs(req_id, blobs).map_err(|e| {
                        RpcResponseError::BlockComponentCouplingError(CouplingError::InternalError(
                            e,
                        ))
                    })
                }),
                RangeBlockComponent::CustodyColumns(req_id, resp) => {
                    resp.and_then(|(custody_columns, _)| {
                        request
                            .add_custody_columns(req_id, custody_columns)
                            .map_err(|e| {
                                RpcResponseError::BlockComponentCouplingError(
                                    CouplingError::InternalError(e),
                                )
                            })
                    })
                }
            }
        } {
            entry.remove();
            return Some(Err(e));
        }

        let range_req = entry.get_mut();
        if let Some(blocks_result) = range_req.responses(&self.chain.spec) {
            if let Err(CouplingError::DataColumnPeerFailure {
                error,
                faulty_peers: _,
                exceeded_retries,
            }) = &blocks_result
            {
                // Remove the entry if it's a peer failure **and** retry counter is exceeded
                if *exceeded_retries {
                    debug!(
                        entry=?entry.key(),
                        msg = error,
                        "Request exceeded max retries, failing batch"
                    );
                    entry.remove();
                };
            } else {
                // also remove the entry only if it coupled successfully
                // or if it isn't a column peer failure.
                entry.remove();
            }
            // If the request is finished, dequeue everything
            Some(blocks_result.map_err(RpcResponseError::BlockComponentCouplingError))
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
        lookup_peers: Arc<RwLock<HashSet<PeerId>>>,
        block_root: Hash256,
    ) -> Result<LookupRequestResult, RpcRequestSendError> {
        let active_request_count_by_peer = self.active_request_count_by_peer();
        let Some(peer_id) = lookup_peers
            .read()
            .iter()
            .map(|peer| {
                (
                    // Prefer peers with less overall requests
                    active_request_count_by_peer.get(peer).copied().unwrap_or(0),
                    // Random factor to break ties, otherwise the PeerID breaks ties
                    rand::random::<u32>(),
                    peer,
                )
            })
            .min()
            .map(|(_, _, peer)| *peer)
        else {
            // Allow lookup to not have any peers and do nothing. This is an optimization to not
            // lose progress of lookups created from a block with unknown parent before we receive
            // attestations for said block.
            // Lookup sync event safety: If a lookup requires peers to make progress, and does
            // not receive any new peers for some time it will be dropped. If it receives a new
            // peer it must attempt to make progress.
            return Ok(LookupRequestResult::Pending("no peers"));
        };

        match self.chain.get_block_process_status(&block_root) {
            // Unknown block, continue request to download
            BlockProcessStatus::Unknown => {}
            // Block is known and currently processing. Imports from gossip and HTTP API insert the
            // block in the da_cache. However, HTTP API is unable to notify sync when it completes
            // block import. Returning `Pending` here will result in stuck lookups if the block is
            // importing from sync.
            BlockProcessStatus::NotValidated(_, source) => match source {
                BlockImportSource::Gossip => {
                    // Lookup sync event safety: If the block is currently in the processing cache, we
                    // are guaranteed to receive a `SyncMessage::GossipBlockProcessResult` that will
                    // make progress on this lookup
                    return Ok(LookupRequestResult::Pending("block in processing cache"));
                }
                BlockImportSource::Lookup
                | BlockImportSource::RangeSync
                | BlockImportSource::HttpApi => {
                    // Lookup, RangeSync or HttpApi block import don't emit the GossipBlockProcessResult
                    // event. If a lookup happens to be created during block import from one of
                    // those sources just import the block twice. Otherwise the lookup will get
                    // stuck. Double imports are fine, they just waste resources.
                }
            },
            // Block is fully validated. If it's not yet imported it's waiting for missing block
            // components. Consider this request completed and do nothing.
            BlockProcessStatus::ExecutionValidated { .. } => {
                return Ok(LookupRequestResult::NoRequestNeeded(
                    "block execution validated",
                ));
            }
        }

        let id = SingleLookupReqId {
            lookup_id,
            req_id: self.next_id(),
        };

        let request = BlocksByRootSingleRequest(block_root);

        // Lookup sync event safety: If network_send.send() returns Ok(_) we are guaranteed that
        // eventually at least one this 3 events will be received:
        // - StreamTermination(request_id): handled by `Self::on_single_block_response`
        // - RPCError(request_id): handled by `Self::on_single_block_response`
        // - Disconnect(peer_id) handled by `Self::peer_disconnected``which converts it to a
        // ` RPCError(request_id)`event handled by the above method
        let network_request = RequestType::BlocksByRoot(
            request
                .into_request(&self.fork_context)
                .map_err(RpcRequestSendError::InternalError)?,
        );
        self.network_send
            .send(NetworkMessage::SendRequest {
                peer_id,
                request: network_request,
                app_request_id: AppRequestId::Sync(SyncRequestId::SingleBlock { id }),
            })
            .map_err(|_| RpcRequestSendError::InternalError("network send error".to_owned()))?;

        debug!(
            method = "BlocksByRoot",
            ?block_root,
            peer = %peer_id,
            %id,
            "Sync RPC request sent"
        );

        let request_span = debug_span!(
            parent: Span::current(),
            SPAN_OUTGOING_BLOCK_BY_ROOT_REQUEST,
            %block_root,
        );
        self.blocks_by_root_requests.insert(
            id,
            peer_id,
            // true = enforce max_requests as returned for blocks_by_root. We always request a single
            // block and the peer must have it.
            true,
            BlocksByRootRequestItems::new(request),
            request_span,
        );

        Ok(LookupRequestResult::RequestSent(id.req_id))
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
        lookup_peers: Arc<RwLock<HashSet<PeerId>>>,
        block_root: Hash256,
        expected_blobs: usize,
    ) -> Result<LookupRequestResult, RpcRequestSendError> {
        let active_request_count_by_peer = self.active_request_count_by_peer();
        let Some(peer_id) = lookup_peers
            .read()
            .iter()
            .map(|peer| {
                (
                    // Prefer peers with less overall requests
                    active_request_count_by_peer.get(peer).copied().unwrap_or(0),
                    // Random factor to break ties, otherwise the PeerID breaks ties
                    rand::random::<u32>(),
                    peer,
                )
            })
            .min()
            .map(|(_, _, peer)| *peer)
        else {
            // Allow lookup to not have any peers and do nothing. This is an optimization to not
            // lose progress of lookups created from a block with unknown parent before we receive
            // attestations for said block.
            // Lookup sync event safety: If a lookup requires peers to make progress, and does
            // not receive any new peers for some time it will be dropped. If it receives a new
            // peer it must attempt to make progress.
            return Ok(LookupRequestResult::Pending("no peers"));
        };

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

        let id = SingleLookupReqId {
            lookup_id,
            req_id: self.next_id(),
        };

        let request = BlobsByRootSingleBlockRequest {
            block_root,
            indices: indices.clone(),
        };

        // Lookup sync event safety: Refer to `Self::block_lookup_request` `network_send.send` call
        let network_request = RequestType::BlobsByRoot(
            request
                .clone()
                .into_request(&self.fork_context)
                .map_err(RpcRequestSendError::InternalError)?,
        );
        self.network_send
            .send(NetworkMessage::SendRequest {
                peer_id,
                request: network_request,
                app_request_id: AppRequestId::Sync(SyncRequestId::SingleBlob { id }),
            })
            .map_err(|_| RpcRequestSendError::InternalError("network send error".to_owned()))?;

        debug!(
            method = "BlobsByRoot",
            ?block_root,
            blob_indices = ?indices,
            peer = %peer_id,
            %id,
            "Sync RPC request sent"
        );

        self.blobs_by_root_requests.insert(
            id,
            peer_id,
            // true = enforce max_requests are returned for blobs_by_root. We only issue requests for
            // blocks after we know the block has data, and only request peers after they claim to
            // have imported the block+blobs.
            true,
            BlobsByRootRequestItems::new(request),
            // Not implemented
            Span::none(),
        );

        Ok(LookupRequestResult::RequestSent(id.req_id))
    }

    /// Request to send a single `data_columns_by_root` request to the network.
    pub fn data_column_lookup_request(
        &mut self,
        requester: DataColumnsByRootRequester,
        peer_id: PeerId,
        request: DataColumnsByRootSingleBlockRequest,
        expect_max_responses: bool,
    ) -> Result<LookupRequestResult<DataColumnsByRootRequestId>, &'static str> {
        let id = DataColumnsByRootRequestId {
            id: self.next_id(),
            requester,
        };

        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request: RequestType::DataColumnsByRoot(
                request.clone().try_into_request::<T::EthSpec>(
                    self.fork_context.current_fork_name(),
                    &self.chain.spec,
                )?,
            ),
            app_request_id: AppRequestId::Sync(SyncRequestId::DataColumnsByRoot(id)),
        })?;

        debug!(
            method = "DataColumnsByRoot",
            block_root = ?request.block_root,
            indices = ?request.indices,
            peer = %peer_id,
            %id,
            "Sync RPC request sent"
        );

        self.data_columns_by_root_requests.insert(
            id,
            peer_id,
            expect_max_responses,
            DataColumnsByRootRequestItems::new(request),
            // Span is tracked in `self.custody_columns_by_root_requests` in the
            // `ActiveCustodyRequest` struct.
            Span::none(),
        );

        Ok(LookupRequestResult::RequestSent(id))
    }

    /// Request to fetch all needed custody columns of a specific block. This function may not send
    /// any request to the network if no columns have to be fetched based on the import state of the
    /// node. A custody request is a "super request" that may trigger 0 or more `data_columns_by_root`
    /// requests.
    pub fn custody_lookup_request(
        &mut self,
        lookup_id: SingleLookupId,
        block_root: Hash256,
        lookup_peers: Arc<RwLock<HashSet<PeerId>>>,
    ) -> Result<LookupRequestResult, RpcRequestSendError> {
        let custody_indexes_imported = self
            .chain
            .data_availability_checker
            .cached_data_column_indexes(&block_root)
            .unwrap_or_default();

        let current_epoch = self.chain.epoch().map_err(|e| {
            RpcRequestSendError::InternalError(format!("Unable to read slot clock {:?}", e))
        })?;

        // Include only the blob indexes not yet imported (received through gossip)
        let custody_indexes_to_fetch = self
            .chain
            .sampling_columns_for_epoch(current_epoch)
            .iter()
            .copied()
            .filter(|index| !custody_indexes_imported.contains(index))
            .collect::<Vec<_>>();

        if custody_indexes_to_fetch.is_empty() {
            // No indexes required, do not issue any request
            return Ok(LookupRequestResult::NoRequestNeeded("no indices to fetch"));
        }

        let id = SingleLookupReqId {
            lookup_id,
            req_id: self.next_id(),
        };

        debug!(
            ?block_root,
            indices = ?custody_indexes_to_fetch,
            %id,
            "Starting custody columns request"
        );

        let requester = CustodyRequester(id);
        let mut request = ActiveCustodyRequest::new(
            block_root,
            CustodyId { requester },
            &custody_indexes_to_fetch,
            lookup_peers,
        );

        // Note that you can only send, but not handle a response here
        match request.continue_requests(self) {
            Ok(_) => {
                // Ignoring the result of `continue_requests` is okay. A request that has just been
                // created cannot return data immediately, it must send some request to the network
                // first. And there must exist some request, `custody_indexes_to_fetch` is not empty.
                self.custody_by_root_requests.insert(requester, request);
                Ok(LookupRequestResult::RequestSent(id.req_id))
            }
            Err(e) => Err(match e {
                CustodyRequestError::NoPeer(column_index) => {
                    RpcRequestSendError::NoPeer(NoPeerError::CustodyPeer(column_index))
                }
                // - TooManyFailures: Should never happen, `request` has just been created, it's
                //   count of download_failures is 0 here
                // - BadState: Should never happen, a bad state can only happen when handling a
                //   network response
                // - UnexpectedRequestId: Never happens: this Err is only constructed handling a
                //   download or processing response
                // - SendFailed: Should never happen unless in a bad drop sequence when shutting
                //   down the node
                e @ (CustodyRequestError::TooManyFailures
                | CustodyRequestError::BadState { .. }
                | CustodyRequestError::UnexpectedRequestId { .. }
                | CustodyRequestError::SendFailed { .. }) => {
                    RpcRequestSendError::InternalError(format!("{e:?}"))
                }
            }),
        }
    }

    fn send_blocks_by_range_request(
        &mut self,
        peer_id: PeerId,
        request: BlocksByRangeRequest,
        parent_request_id: ComponentsByRangeRequestId,
        request_span: Span,
    ) -> Result<BlocksByRangeRequestId, RpcRequestSendError> {
        let id = BlocksByRangeRequestId {
            id: self.next_id(),
            parent_request_id,
        };
        self.network_send
            .send(NetworkMessage::SendRequest {
                peer_id,
                request: RequestType::BlocksByRange(request.clone().into()),
                app_request_id: AppRequestId::Sync(SyncRequestId::BlocksByRange(id)),
            })
            .map_err(|_| RpcRequestSendError::InternalError("network send error".to_owned()))?;

        debug!(
            method = "BlocksByRange",
            slots = request.count(),
            epoch = %Slot::new(*request.start_slot()).epoch(T::EthSpec::slots_per_epoch()),
            peer = %peer_id,
            %id,
            "Sync RPC request sent"
        );

        self.blocks_by_range_requests.insert(
            id,
            peer_id,
            // false = do not enforce max_requests are returned for *_by_range methods. We don't
            // know if there are missed blocks.
            false,
            BlocksByRangeRequestItems::new(request),
            request_span,
        );
        Ok(id)
    }

    fn send_blobs_by_range_request(
        &mut self,
        peer_id: PeerId,
        request: BlobsByRangeRequest,
        parent_request_id: ComponentsByRangeRequestId,
        request_span: Span,
    ) -> Result<BlobsByRangeRequestId, RpcRequestSendError> {
        let id = BlobsByRangeRequestId {
            id: self.next_id(),
            parent_request_id,
        };
        let request_epoch = Slot::new(request.start_slot).epoch(T::EthSpec::slots_per_epoch());

        // Create the blob request based on the blocks request.
        self.network_send
            .send(NetworkMessage::SendRequest {
                peer_id,
                request: RequestType::BlobsByRange(request.clone()),
                app_request_id: AppRequestId::Sync(SyncRequestId::BlobsByRange(id)),
            })
            .map_err(|_| RpcRequestSendError::InternalError("network send error".to_owned()))?;

        debug!(
            method = "BlobsByRange",
            slots = request.count,
            epoch = %request_epoch,
            peer = %peer_id,
            %id,
            "Sync RPC request sent"
        );

        let max_blobs_per_block = self.chain.spec.max_blobs_per_block(request_epoch);
        self.blobs_by_range_requests.insert(
            id,
            peer_id,
            // false = do not enforce max_requests are returned for *_by_range methods. We don't
            // know if there are missed blocks.
            false,
            BlobsByRangeRequestItems::new(request, max_blobs_per_block),
            request_span,
        );
        Ok(id)
    }

    fn send_data_columns_by_range_request(
        &mut self,
        peer_id: PeerId,
        request: DataColumnsByRangeRequest,
        parent_request_id: DataColumnsByRangeRequester,
        request_span: Span,
    ) -> Result<(DataColumnsByRangeRequestId, Vec<u64>), RpcRequestSendError> {
        let requested_columns = request.columns.clone();
        let id = DataColumnsByRangeRequestId {
            id: self.next_id(),
            parent_request_id,
            peer: peer_id,
        };

        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request: RequestType::DataColumnsByRange(request.clone()),
            app_request_id: AppRequestId::Sync(SyncRequestId::DataColumnsByRange(id)),
        })
        .map_err(|_| RpcRequestSendError::InternalError("network send error".to_owned()))?;

        debug!(
            method = "DataColumnsByRange",
            slots = request.count,
            epoch = %Slot::new(request.start_slot).epoch(T::EthSpec::slots_per_epoch()),
            columns = ?request.columns,
            peer = %peer_id,
            %id,
            "Sync RPC request sent"
        );

        self.data_columns_by_range_requests.insert(
            id,
            peer_id,
            // false = do not enforce max_requests are returned for *_by_range methods. We don't
            // know if there are missed blocks.
            false,
            DataColumnsByRangeRequestItems::new(request),
            request_span,
        );
        Ok((id, requested_columns))
    }

    pub fn is_execution_engine_online(&self) -> bool {
        self.execution_engine_state == EngineState::Online
    }

    pub fn update_execution_engine_state(&mut self, engine_state: EngineState) {
        debug!(past_state = ?self.execution_engine_state, new_state = ?engine_state, "Sync's view on execution engine state updated");
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
                warn!("Could not report peer: channel failed");
            });
    }

    /// Reports to the scoring algorithm the behaviour of a peer.
    pub fn report_peer(&self, peer_id: PeerId, action: PeerAction, msg: &'static str) {
        debug!(%peer_id, %action, %msg, "Sync reporting peer");
        self.network_send
            .send(NetworkMessage::ReportPeer {
                peer_id,
                action,
                source: ReportSource::SyncService,
                msg,
            })
            .unwrap_or_else(|e| {
                warn!(error = %e, "Could not report peer: channel failed");
            });
    }

    /// Subscribes to core topics.
    pub fn subscribe_core_topics(&self) {
        self.network_send
            .send(NetworkMessage::SubscribeCoreTopics)
            .unwrap_or_else(|e| {
                warn!(error = %e, "Could not subscribe to core topics.");
            });
    }

    /// Sends an arbitrary network message.
    fn send_network_msg(&self, msg: NetworkMessage<T::EthSpec>) -> Result<(), &'static str> {
        self.network_send.send(msg).map_err(|_| {
            debug!("Could not send message to the network service");
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
        let resp = self.blocks_by_root_requests.on_response(id, rpc_event);
        let resp = resp.map(|res| {
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
        self.on_rpc_response_result(id, "BlocksByRoot", resp, peer_id, |_| 1)
    }

    pub(crate) fn on_single_blob_response(
        &mut self,
        id: SingleLookupReqId,
        peer_id: PeerId,
        rpc_event: RpcEvent<Arc<BlobSidecar<T::EthSpec>>>,
    ) -> Option<RpcResponseResult<FixedBlobSidecarList<T::EthSpec>>> {
        let resp = self.blobs_by_root_requests.on_response(id, rpc_event);
        let resp = resp.map(|res| {
            res.and_then(|(blobs, seen_timestamp)| {
                if let Some(max_len) = blobs
                    .first()
                    .map(|blob| self.chain.spec.max_blobs_per_block(blob.epoch()) as usize)
                {
                    match to_fixed_blob_sidecar_list(blobs, max_len) {
                        Ok(blobs) => Ok((blobs, seen_timestamp)),
                        Err(e) => Err(e.into()),
                    }
                } else {
                    Err(RpcResponseError::VerifyError(
                        LookupVerifyError::InternalError(
                            "Requested blobs for a block that has no blobs".to_string(),
                        ),
                    ))
                }
            })
        });
        self.on_rpc_response_result(id, "BlobsByRoot", resp, peer_id, |_| 1)
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
        self.on_rpc_response_result(id, "DataColumnsByRoot", resp, peer_id, |_| 1)
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn on_blocks_by_range_response(
        &mut self,
        id: BlocksByRangeRequestId,
        peer_id: PeerId,
        rpc_event: RpcEvent<Arc<SignedBeaconBlock<T::EthSpec>>>,
    ) -> Option<RpcResponseResult<Vec<Arc<SignedBeaconBlock<T::EthSpec>>>>> {
        let resp = self.blocks_by_range_requests.on_response(id, rpc_event);
        self.on_rpc_response_result(id, "BlocksByRange", resp, peer_id, |b| b.len())
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn on_blobs_by_range_response(
        &mut self,
        id: BlobsByRangeRequestId,
        peer_id: PeerId,
        rpc_event: RpcEvent<Arc<BlobSidecar<T::EthSpec>>>,
    ) -> Option<RpcResponseResult<Vec<Arc<BlobSidecar<T::EthSpec>>>>> {
        let resp = self.blobs_by_range_requests.on_response(id, rpc_event);
        self.on_rpc_response_result(id, "BlobsByRangeRequest", resp, peer_id, |b| b.len())
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn on_data_columns_by_range_response(
        &mut self,
        id: DataColumnsByRangeRequestId,
        peer_id: PeerId,
        rpc_event: RpcEvent<Arc<DataColumnSidecar<T::EthSpec>>>,
    ) -> Option<RpcResponseResult<DataColumnSidecarList<T::EthSpec>>> {
        let resp = self
            .data_columns_by_range_requests
            .on_response(id, rpc_event);
        self.on_rpc_response_result(id, "DataColumnsByRange", resp, peer_id, |d| d.len())
    }

    fn on_rpc_response_result<I: std::fmt::Display, R, F: FnOnce(&R) -> usize>(
        &mut self,
        id: I,
        method: &'static str,
        resp: Option<RpcResponseResult<R>>,
        peer_id: PeerId,
        get_count: F,
    ) -> Option<RpcResponseResult<R>> {
        match &resp {
            None => {}
            Some(Ok((v, _))) => {
                debug!(
                    %id,
                    method,
                    count = get_count(v),
                    "Sync RPC request completed"
                );
            }
            Some(Err(e)) => {
                debug!(
                    %id,
                    method,
                    error = ?e,
                    "Sync RPC request error"
                );
            }
        }
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
            debug!(?id, "Custody column downloaded event for unknown request");
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
            Some(Ok((columns, peer_group, _))) => {
                debug!(?id, count = columns.len(), peers = ?peer_group, "Custody request success, removing")
            }
            Some(Err(e)) => {
                debug!(?id, error = ?e, "Custody request failure, removing" )
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
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
        seen_timestamp: Duration,
    ) -> Result<(), SendErrorProcessor> {
        let beacon_processor = self
            .beacon_processor_if_enabled()
            .ok_or(SendErrorProcessor::ProcessorNotAvailable)?;

        let block = RpcBlock::new_without_blobs(Some(block_root), block);

        debug!(block = ?block_root, id, "Sending block for processing");
        // Lookup sync event safety: If `beacon_processor.send_rpc_beacon_block` returns Ok() sync
        // must receive a single `SyncMessage::BlockComponentProcessed` with this process type
        beacon_processor
            .send_rpc_beacon_block(
                block_root,
                block,
                seen_timestamp,
                BlockProcessType::SingleBlock { id },
            )
            .map_err(|e| {
                error!(
                    error = ?e,
                    "Failed to send sync block to processor"
                );
                SendErrorProcessor::SendError
            })
    }

    pub fn send_blobs_for_processing(
        &self,
        id: Id,
        block_root: Hash256,
        blobs: FixedBlobSidecarList<T::EthSpec>,
        seen_timestamp: Duration,
    ) -> Result<(), SendErrorProcessor> {
        let beacon_processor = self
            .beacon_processor_if_enabled()
            .ok_or(SendErrorProcessor::ProcessorNotAvailable)?;

        debug!(?block_root, ?id, "Sending blobs for processing");
        // Lookup sync event safety: If `beacon_processor.send_rpc_blobs` returns Ok() sync
        // must receive a single `SyncMessage::BlockComponentProcessed` event with this process type
        beacon_processor
            .send_rpc_blobs(
                block_root,
                blobs,
                seen_timestamp,
                BlockProcessType::SingleBlob { id },
            )
            .map_err(|e| {
                error!(
                    error = ?e,
                    "Failed to send sync blobs to processor"
                );
                SendErrorProcessor::SendError
            })
    }

    pub fn send_custody_columns_for_processing(
        &self,
        _id: Id,
        block_root: Hash256,
        custody_columns: DataColumnSidecarList<T::EthSpec>,
        seen_timestamp: Duration,
        process_type: BlockProcessType,
    ) -> Result<(), SendErrorProcessor> {
        let beacon_processor = self
            .beacon_processor_if_enabled()
            .ok_or(SendErrorProcessor::ProcessorNotAvailable)?;

        debug!(
            ?block_root,
            ?process_type,
            "Sending custody columns for processing"
        );

        beacon_processor
            .send_rpc_custody_columns(block_root, custody_columns, seen_timestamp, process_type)
            .map_err(|e| {
                error!(
                    error = ?e,
                    "Failed to send sync custody columns to processor"
                );
                SendErrorProcessor::SendError
            })
    }

    /// data column by range requests sent by the custody sync algorithm
    pub fn custody_backfill_data_columns_batch_request(
        &mut self,
        request: DataColumnsByRangeRequest,
        batch_id: CustodyBackfillBatchId,
        peers: &HashSet<PeerId>,
        peers_to_deprioritize: &HashSet<PeerId>,
    ) -> Result<CustodyBackFillBatchRequestId, RpcRequestSendError> {
        let active_request_count_by_peer = self.active_request_count_by_peer();
        // Attempt to find all required custody peers before sending any request or creating an ID
        let columns_by_range_peers_to_request = {
            let column_indexes = self
                .chain
                .sampling_columns_for_epoch(batch_id.epoch)
                .iter()
                .cloned()
                .collect();

            self.select_columns_by_range_peers_to_request(
                &column_indexes,
                peers,
                active_request_count_by_peer,
                peers_to_deprioritize,
            )?
        };

        // Create the overall `custody_by_range` request id
        let id = CustodyBackFillBatchRequestId {
            id: self.next_id(),
            batch_id,
        };

        let result = columns_by_range_peers_to_request
            .iter()
            .filter_map(|(peer_id, _)| {
                self.send_data_columns_by_range_request(
                    *peer_id,
                    request.clone(),
                    DataColumnsByRangeRequester::CustodyBackfillSync(id),
                    Span::none(),
                )
                .ok()
            })
            .collect::<Vec<_>>();

        let range_data_column_batch_request =
            RangeDataColumnBatchRequest::new(result, self.chain.clone(), batch_id.epoch);

        self.custody_backfill_data_column_batch_requests
            .insert(id, range_data_column_batch_request);

        Ok(id)
    }

    /// Received a data columns by range response from a custody sync request which batches them.
    pub fn custody_backfill_data_columns_response(
        &mut self,
        // Identifies the custody backfill request for all data columns on this epoch
        custody_sync_request_id: CustodyBackFillBatchRequestId,
        // Identifies a specific data_columns_by_range request for *some* columns in this epoch. We
        // pass them separately as DataColumnsByRangeRequestId parent is an enum and would require
        // matching again.
        req_id: DataColumnsByRangeRequestId,
        data_columns: RpcResponseResult<DataColumnSidecarList<T::EthSpec>>,
    ) -> Option<Result<DataColumnSidecarList<T::EthSpec>, RpcResponseError>> {
        let Entry::Occupied(mut entry) = self
            .custody_backfill_data_column_batch_requests
            .entry(custody_sync_request_id)
        else {
            metrics::inc_counter_vec(
                &metrics::SYNC_UNKNOWN_NETWORK_REQUESTS,
                &["range_data_columns"],
            );
            return None;
        };

        if let Err(e) = {
            let request = entry.get_mut();
            data_columns.and_then(|(data_columns, _)| {
                request
                    .add_custody_columns(req_id, data_columns.clone())
                    .map_err(|e| {
                        RpcResponseError::BlockComponentCouplingError(CouplingError::InternalError(
                            e,
                        ))
                    })
            })
        } {
            entry.remove();
            return Some(Err(e));
        }

        if let Some(data_column_result) = entry.get_mut().responses() {
            if data_column_result.is_ok() {
                // remove the entry only if it coupled successfully with
                // no errors
                entry.remove();
            }
            // If the request is finished, dequeue everything
            Some(data_column_result.map_err(RpcResponseError::BlockComponentCouplingError))
        } else {
            None
        }
    }

    pub(crate) fn register_metrics(&self) {
        for (id, count) in [
            ("blocks_by_root", self.blocks_by_root_requests.len()),
            ("blobs_by_root", self.blobs_by_root_requests.len()),
            (
                "data_columns_by_root",
                self.data_columns_by_root_requests.len(),
            ),
            ("blocks_by_range", self.blocks_by_range_requests.len()),
            ("blobs_by_range", self.blobs_by_range_requests.len()),
            (
                "data_columns_by_range",
                self.data_columns_by_range_requests.len(),
            ),
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
    max_len: usize,
) -> Result<FixedBlobSidecarList<E>, LookupVerifyError> {
    let mut fixed_list = FixedBlobSidecarList::new(vec![None; max_len]);
    for blob in blobs.into_iter() {
        let index = blob.index as usize;
        *fixed_list
            .get_mut(index)
            .ok_or(LookupVerifyError::UnrequestedIndex(index as u64))? = Some(blob)
    }
    Ok(fixed_list)
}
