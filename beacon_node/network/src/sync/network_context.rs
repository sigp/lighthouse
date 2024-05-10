//! Provides network functionality for the Syncing thread. This fundamentally wraps a network
//! channel and stores a global RPC ID to perform requests.

pub use self::custody::CustodyId;
use self::custody::{ActiveCustodyRequest, CustodyRequester, Error as CustodyRequestError};
use self::requests::{
    ActiveBlobsByRootRequest, ActiveBlocksByRootRequest, ActiveDataColumnsByRootRequest,
};
pub use self::requests::{
    BlobsByRootSingleBlockRequest, BlocksByRootSingleRequest, DataColumnsByRootSingleBlockRequest,
};
use super::block_sidecar_coupling::RangeBlockComponentsRequest;
use super::manager::{
    BlockProcessType, DataColumnsByRootRequestId, DataColumnsByRootRequester, Id,
    RequestId as SyncRequestId,
};
use super::range_sync::{BatchId, ByRangeRequestType, ChainId};
use crate::network_beacon_processor::NetworkBeaconProcessor;
use crate::service::{NetworkMessage, RequestId};
use crate::status::ToStatusMessage;
use crate::sync::block_lookups::SingleLookupId;
use crate::sync::manager::SingleLookupReqId;
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::data_column_verification::CustodyDataColumn;
use beacon_chain::validator_monitor::timestamp_now;
use beacon_chain::{BeaconChain, BeaconChainTypes, EngineState};
use fnv::FnvHashMap;
use lighthouse_network::rpc::methods::{BlobsByRangeRequest, DataColumnsByRangeRequest};
use lighthouse_network::rpc::{BlocksByRangeRequest, GoodbyeReason, RPCError};
use lighthouse_network::{
    Client, Eth2Enr, NetworkGlobals, PeerAction, PeerId, ReportSource, Request,
};
pub use requests::LookupVerifyError;
use slog::{debug, error, trace, warn};
use slot_clock::SlotClock;
use std::collections::hash_map::Entry;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use types::blob_sidecar::FixedBlobSidecarList;
use types::{
    BlobSidecar, ColumnIndex, DataColumnSidecar, DataColumnSubnetId, Epoch, EthSpec, Hash256,
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

pub type RpcProcessingResult<T> = Result<(T, Duration), LookupFailure>;

#[derive(Debug)]
pub enum LookupFailure {
    RpcError(RPCError),
    LookupVerifyError(LookupVerifyError),
    CustodyRequestError(CustodyRequestError),
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

#[derive(Clone, Debug)]
pub struct PeerGroup {
    peers: Vec<PeerId>,
}

impl PeerGroup {
    pub fn from_single(peer: PeerId) -> Self {
        Self { peers: vec![peer] }
    }
    pub fn from_set(peers: Vec<PeerId>) -> Self {
        Self { peers }
    }
    pub fn all(&self) -> &[PeerId] {
        &self.peers
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
    data_columns_by_root_requests: FnvHashMap<
        DataColumnsByRootRequestId,
        ActiveDataColumnsByRootRequest<T::EthSpec, DataColumnsByRootRequester>,
    >,
    /// Mapping of active custody column requests for a block root
    custody_by_root_requests: FnvHashMap<CustodyRequester, ActiveCustodyRequest<T>>,

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

    // TODO(das): epoch argument left here in case custody rotation is implemented
    pub fn get_custodial_peers(&self, _epoch: Epoch, column_index: ColumnIndex) -> Vec<PeerId> {
        let mut peer_ids = vec![];

        for (peer_id, peer_info) in self.network_globals().peers.read().connected_peers() {
            if let Some(enr) = peer_info.enr() {
                // TODO(das): ignores decode errors
                let custody_subnet_count = enr
                    .custody_subnet_count::<T::EthSpec>()
                    .unwrap_or(T::EthSpec::min_custody_requirement() as u64);
                // TODO(das): consider caching a map of subnet -> Vec<PeerId> and invalidating
                // whenever a peer connected or disconnect event in received
                let mut subnets = DataColumnSubnetId::compute_custody_subnets::<T::EthSpec>(
                    enr.node_id().raw().into(),
                    custody_subnet_count,
                );
                if subnets.any(|subnet| {
                    subnet
                        .columns::<T::EthSpec>()
                        .any(|index| index == column_index)
                }) {
                    peer_ids.push(*peer_id)
                }
            }
        }

        peer_ids
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

    /// A blocks by range request sent by the range sync algorithm
    pub fn block_components_by_range_request(
        &mut self,
        peer_id: PeerId,
        batch_type: ByRangeRequestType,
        request: BlocksByRangeRequest,
        sender_id: RangeRequestId,
    ) -> Result<Id, &'static str> {
        let epoch = Slot::new(*request.start_slot()).epoch(T::EthSpec::slots_per_epoch());
        let id = self.next_id();
        debug!(
            self.log,
            "Sending BlocksByRange request";
            "method" => "BlocksByRange",
            "count" => request.count(),
            "epoch" => epoch,
            "peer" => %peer_id,
        );
        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request: Request::BlocksByRange(request.clone()),
            request_id: RequestId::Sync(SyncRequestId::RangeBlockComponents(id)),
        })?;

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
            self.send_network_msg(NetworkMessage::SendRequest {
                peer_id,
                request: Request::BlobsByRange(BlobsByRangeRequest {
                    start_slot: *request.start_slot(),
                    count: *request.count(),
                }),
                request_id: RequestId::Sync(SyncRequestId::RangeBlockComponents(id)),
            })?;
            true
        } else {
            false
        };

        let expects_custody_columns = if matches!(batch_type, ByRangeRequestType::BlocksAndColumns)
        {
            let custody_indexes = self.network_globals().custody_columns(epoch)?;

            for column_index in &custody_indexes {
                let custody_peer_ids = self.get_custodial_peers(epoch, *column_index);
                let Some(custody_peer) = custody_peer_ids.first().cloned() else {
                    // TODO(das): this will be pretty bad UX. To improve we should:
                    // - Attempt to fetch custody requests first, before requesting blocks
                    // - Handle the no peers case gracefully, maybe add some timeout and give a few
                    //   minutes / seconds to the peer manager to locate peers on this subnet before
                    //   abandoing progress on the chain completely.
                    return Err("no custody peer");
                };

                debug!(
                    self.log,
                    "Sending DataColumnsByRange requests";
                    "method" => "DataColumnsByRange",
                    "count" => request.count(),
                    "epoch" => epoch,
                    "index" => column_index,
                    "peer" => %custody_peer,
                );

                // Create the blob request based on the blocks request.
                self.send_network_msg(NetworkMessage::SendRequest {
                    peer_id: custody_peer,
                    request: Request::DataColumnsByRange(DataColumnsByRangeRequest {
                        start_slot: *request.start_slot(),
                        count: *request.count(),
                        columns: vec![*column_index],
                    }),
                    request_id: RequestId::Sync(SyncRequestId::RangeBlockComponents(id)),
                })?;
            }

            Some(custody_indexes)
        } else {
            None
        };

        let info = RangeBlockComponentsRequest::new(expected_blobs, expects_custody_columns);
        self.range_block_components_requests
            .insert(id, (sender_id, info));
        Ok(id)
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
        match self.range_block_components_requests.entry(request_id) {
            Entry::Occupied(mut entry) => {
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
                        responses: info.into_responses(),
                        expects_blobs,
                        expects_custody_columns,
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
        // Check if we are into deneb, and before peerdas
        if !self
            .chain
            .data_availability_checker
            .blobs_required_for_epoch(
                // TODO(das): use the block's slot
                self.chain
                    .slot_clock
                    .now_or_genesis()
                    .ok_or("clock not available")?
                    .epoch(T::EthSpec::slots_per_epoch()),
            )
        {
            return Ok(false);
        }

        let expected_blobs = downloaded_block_expected_blobs
            .or_else(|| {
                self.chain
                    .data_availability_checker
                    .num_expected_blobs(&block_root)
            })
            .unwrap_or(
                // If we don't about the block being requested, attempt to fetch all blobs
                T::EthSpec::max_blobs_per_block(),
            );

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

    pub fn data_column_lookup_request(
        &mut self,
        requester: DataColumnsByRootRequester,
        peer_id: PeerId,
        request: DataColumnsByRootSingleBlockRequest,
    ) -> Result<(), &'static str> {
        let req_id = self.next_id();
        debug!(
            self.log,
            "Sending DataColumnsByRoot Request";
            "method" => "DataColumnsByRoot",
            "block_root" => ?request.block_root,
            "indices" => ?request.indices,
            "peer" => %peer_id,
            "requester" => ?requester,
            "id" => req_id,
        );
        let id = DataColumnsByRootRequestId { requester, req_id };

        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request: Request::DataColumnsByRoot(request.clone().into_request(&self.chain.spec)),
            request_id: RequestId::Sync(SyncRequestId::DataColumnsByRoot(id)),
        })?;

        self.data_columns_by_root_requests
            .insert(id, ActiveDataColumnsByRootRequest::new(request, requester));

        Ok(())
    }

    pub fn custody_lookup_request(
        &mut self,
        lookup_id: SingleLookupId,
        block_root: Hash256,
        downloaded_block_expected_data: Option<usize>,
    ) -> Result<bool, &'static str> {
        // Check if we are into peerdas
        if !self
            .chain
            .data_availability_checker
            .data_columns_required_for_epoch(
                // TODO(das): use the block's slot
                self.chain
                    .slot_clock
                    .now_or_genesis()
                    .ok_or("clock not available")?
                    .epoch(T::EthSpec::slots_per_epoch()),
            )
        {
            return Ok(false);
        }

        let expects_data = downloaded_block_expected_data
            .or_else(|| {
                self.chain
                    .data_availability_checker
                    .num_expected_blobs(&block_root)
            })
            .map(|n| n > 0)
            // If we don't know about the block being requested, assume block has data
            .unwrap_or(true);

        // No data required for this block
        if !expects_data {
            return Ok(false);
        }

        let custody_indexes_imported = self
            .chain
            .data_availability_checker
            .imported_custody_column_indexes(&block_root)
            .unwrap_or_default();

        // TODO(das): figure out how to pass block.slot if we end up doing rotation
        let block_epoch = Epoch::new(0);
        let custody_indexes_duty = self.network_globals().custody_columns(block_epoch)?;

        // Include only the blob indexes not yet imported (received through gossip)
        let custody_indexes_to_fetch = custody_indexes_duty
            .into_iter()
            .filter(|index| !custody_indexes_imported.contains(index))
            .collect::<Vec<_>>();

        if custody_indexes_to_fetch.is_empty() {
            // No indexes required, do not issue any request
            return Ok(false);
        }

        let id = SingleLookupReqId {
            lookup_id,
            req_id: self.next_id(),
        };

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
            requester,
            custody_indexes_to_fetch,
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
                Ok(true)
            }
            // TODO(das): handle this error properly
            Err(_) => Err("custody_send_error"),
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

    pub fn report_peer_on_rpc_error(&self, peer_id: &PeerId, error: &RPCError) {
        // Note: logging the report event here with the full error display. The log inside
        // `report_peer` only includes a smaller string, like "invalid_data"
        debug!(self.log, "reporting peer for sync lookup error"; "error" => %error);
        if let Some(action) = match error {
            // Protocol errors are heavily penalized
            RPCError::SSZDecodeError(..)
            | RPCError::IoError(..)
            | RPCError::ErrorResponse(..)
            | RPCError::InvalidData(..)
            | RPCError::HandlerRejected => Some(PeerAction::LowToleranceError),
            // Timing / network errors are less penalized
            // TODO: Is IoError a protocol error or network error?
            RPCError::StreamTimeout | RPCError::IncompleteStream | RPCError::NegotiationTimeout => {
                Some(PeerAction::MidToleranceError)
            }
            // Not supporting a specific protocol is tolerated. TODO: Are you sure?
            RPCError::UnsupportedProtocol => None,
            // Our fault, don't penalize peer
            RPCError::InternalError(..) | RPCError::Disconnected => None,
        } {
            self.report_peer(*peer_id, action, error.into());
        }
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
        block: RpcEvent<Arc<SignedBeaconBlock<T::EthSpec>>>,
    ) -> Option<RpcProcessingResult<Arc<SignedBeaconBlock<T::EthSpec>>>> {
        let Entry::Occupied(mut request) = self.blocks_by_root_requests.entry(request_id) else {
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

        if let Err(ref e) = resp {
            self.on_lookup_failure(peer_id, e);
        }
        Some(resp)
    }

    pub fn on_single_blob_response(
        &mut self,
        request_id: SingleLookupReqId,
        peer_id: PeerId,
        blob: RpcEvent<Arc<BlobSidecar<T::EthSpec>>>,
    ) -> Option<RpcProcessingResult<FixedBlobSidecarList<T::EthSpec>>> {
        let Entry::Occupied(mut request) = self.blobs_by_root_requests.entry(request_id) else {
            return None;
        };

        let resp = match blob {
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
        };

        if let Err(ref e) = resp {
            self.on_lookup_failure(peer_id, e);
        }
        Some(resp)
    }

    #[allow(clippy::type_complexity)]
    pub fn on_data_columns_by_root_response(
        &mut self,
        id: DataColumnsByRootRequestId,
        peer_id: PeerId,
        item: RpcEvent<Arc<DataColumnSidecar<T::EthSpec>>>,
    ) -> Option<(
        DataColumnsByRootRequester,
        RpcProcessingResult<Vec<Arc<DataColumnSidecar<T::EthSpec>>>>,
    )> {
        let Entry::Occupied(mut request) = self.data_columns_by_root_requests.entry(id) else {
            return None;
        };

        let requester = request.get().requester;

        let resp = match item {
            RpcEvent::Response(item, _) => match request.get_mut().add_response(item) {
                // TODO: Track last chunk timestamp
                Ok(Some(items)) => Ok((items, timestamp_now())),
                Ok(None) => return None,
                Err(e) => {
                    request.remove();
                    Err(e.into())
                }
            },
            RpcEvent::StreamTermination => {
                // Stream terminator
                match request.remove().terminate() {
                    Some(items) => Ok((items, timestamp_now())),
                    None => return None,
                }
            }
            RpcEvent::RPCError(e) => {
                request.remove();
                Err(e.into())
            }
        };

        if let Err(ref e) = resp {
            self.on_lookup_failure(peer_id, e);
        }
        Some((requester, resp))
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
        peer_id: PeerId,
        resp: RpcProcessingResult<Vec<Arc<DataColumnSidecar<T::EthSpec>>>>,
    ) -> Option<(
        CustodyRequester,
        Result<(Vec<CustodyDataColumn<T::EthSpec>>, PeerGroup), LookupFailure>,
    )> {
        // Note: need to remove the request to borrow self again below. Otherwise we can't
        // do nested requests
        let Some(mut request) = self.custody_by_root_requests.remove(&id.id) else {
            // TOOD(das): This log can happen if the request is error'ed early and dropped
            debug!(self.log, "Custody column downloaded event for unknown request"; "id" => ?id);
            return None;
        };

        let result = request
            .on_data_column_downloaded(peer_id, id.column_index, resp, self)
            .map_err(LookupFailure::CustodyRequestError)
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

            Some((id.id, result))
        } else {
            self.custody_by_root_requests.insert(id.id, request);
            None
        }
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

    pub fn send_custody_columns_for_processing(
        &self,
        block_root: Hash256,
        custody_columns: Vec<CustodyDataColumn<T::EthSpec>>,
        duration: Duration,
        process_type: BlockProcessType,
    ) -> Result<(), &'static str> {
        match self.beacon_processor_if_enabled() {
            Some(beacon_processor) => {
                debug!(self.log, "Sending custody columns for processing"; "block" => ?block_root, "process_type" => ?process_type);
                if let Err(e) = beacon_processor.send_rpc_custody_columns(
                    block_root,
                    custody_columns,
                    duration,
                    process_type,
                ) {
                    error!(
                        self.log,
                        "Failed to send sync custody columns to processor";
                        "error" => ?e
                    );
                    Err("beacon processor send failure")
                } else {
                    Ok(())
                }
            }
            None => {
                trace!(self.log, "Dropping custody columns ready for processing. Beacon processor not available"; "block_root" => %block_root);
                Err("beacon processor unavailable")
            }
        }
    }

    /// Downscore peers for lookup errors that originate from sync
    pub fn on_lookup_failure(&self, peer_id: PeerId, err: &LookupFailure) {
        match err {
            // RPCErros are downscored in the network handler
            LookupFailure::RpcError(_) => {}
            // Only downscore lookup verify errors. RPC errors are downscored in the network handler.
            LookupFailure::LookupVerifyError(e) => {
                self.report_peer(peer_id, PeerAction::LowToleranceError, e.into());
            }
            // CustodyRequestError are downscored in the each data_columns_by_root request
            LookupFailure::CustodyRequestError(_) => {}
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
