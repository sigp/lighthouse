//! Provides network functionality for the Syncing thread. This fundamentally wraps a network
//! channel and stores a global RPC ID to perform requests.

use self::requests::{
    ActiveBlobsByRootRequest, ActiveBlocksByRootRequest, ActiveDataColumnsByRootRequest,
};
pub use self::requests::{
    BlobsByRootSingleBlockRequest, BlocksByRootSingleRequest, DataColumnsByRootSingleBlockRequest,
};
use super::block_sidecar_coupling::BlocksAndBlobsRequestInfo;
use super::manager::{DataColumnsByRootRequester, Id, RequestId as SyncRequestId};
use super::range_sync::{BatchId, ByRangeRequestType, ChainId};
use crate::network_beacon_processor::NetworkBeaconProcessor;
use crate::service::{NetworkMessage, RequestId};
use crate::status::ToStatusMessage;
use crate::sync::manager::SingleLookupReqId;
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::validator_monitor::timestamp_now;
use beacon_chain::{BeaconChain, BeaconChainTypes, EngineState};
use fnv::FnvHashMap;
use lighthouse_network::rpc::methods::BlobsByRangeRequest;
use lighthouse_network::rpc::{BlocksByRangeRequest, GoodbyeReason, RPCError};
use lighthouse_network::{
    Client, Eth2Enr, NetworkGlobals, PeerAction, PeerId, ReportSource, Request,
};
pub use requests::LookupVerifyError;
use slog::{debug, trace, warn};
use std::collections::hash_map::Entry;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use types::blob_sidecar::FixedBlobSidecarList;
use types::data_column_sidecar::ColumnIndex;
use types::{
    BlobSidecar, DataColumnSidecar, DataColumnSubnetId, Epoch, EthSpec, SignedBeaconBlock,
};

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

pub type RpcProcessingResult<ID, T> = Option<(ID, Result<(T, Duration), LookupFailure>)>;

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
    data_columns_by_root_requests:
        FnvHashMap<Id, ActiveDataColumnsByRootRequest<T::EthSpec, DataColumnsByRootRequester>>,

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
            data_columns_by_root_requests: <_>::default(),
            range_blocks_and_blobs_requests: FnvHashMap::default(),
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

    pub fn block_lookup_request(
        &mut self,
        id: SingleLookupReqId,
        peer_id: PeerId,
        request: BlocksByRootSingleRequest,
    ) -> Result<(), &'static str> {
        debug!(
            self.log,
            "Sending BlocksByRoot Request";
            "method" => "BlocksByRoot",
            "block_root" => ?request.0,
            "peer" => %peer_id,
            "id" => ?id
        );

        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request: Request::BlocksByRoot(request.into_request(&self.chain.spec)),
            request_id: RequestId::Sync(SyncRequestId::SingleBlock { id }),
        })?;

        self.blocks_by_root_requests
            .insert(id, ActiveBlocksByRootRequest::new(request));

        Ok(())
    }

    pub fn blob_lookup_request(
        &mut self,
        id: SingleLookupReqId,
        peer_id: PeerId,
        request: BlobsByRootSingleBlockRequest,
    ) -> Result<(), &'static str> {
        debug!(
            self.log,
            "Sending BlobsByRoot Request";
            "method" => "BlobsByRoot",
            "block_root" => ?request.block_root,
            "blob_indices" => ?request.indices,
            "peer" => %peer_id,
            "id" => ?id
        );

        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request: Request::BlobsByRoot(request.clone().into_request(&self.chain.spec)),
            request_id: RequestId::Sync(SyncRequestId::SingleBlob { id }),
        })?;

        self.blobs_by_root_requests
            .insert(id, ActiveBlobsByRootRequest::new(request));

        Ok(())
    }

    pub fn data_column_lookup_request(
        &mut self,
        requester: DataColumnsByRootRequester,
        peer_id: PeerId,
        request: DataColumnsByRootSingleBlockRequest,
    ) -> Result<(), &'static str> {
        let id = self.next_id();

        debug!(
            self.log,
            "Sending DataColumnsByRoot Request";
            "method" => "DataColumnsByRoot",
            "block_root" => ?request.block_root,
            "indices" => ?request.indices,
            "peer" => %peer_id,
            "requester" => ?requester,
            "id" => id,
        );

        self.send_network_msg(NetworkMessage::SendRequest {
            peer_id,
            request: Request::DataColumnsByRoot(request.clone().into_request(&self.chain.spec)),
            request_id: RequestId::Sync(SyncRequestId::DataColumnsByRoot(id)),
        })?;

        self.data_columns_by_root_requests
            .insert(id, ActiveDataColumnsByRootRequest::new(request, requester));

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
    ) -> RpcProcessingResult<(), Arc<SignedBeaconBlock<T::EthSpec>>> {
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
        Some(((), resp))
    }

    pub fn on_single_blob_response(
        &mut self,
        request_id: SingleLookupReqId,
        blob: RpcEvent<Arc<BlobSidecar<T::EthSpec>>>,
    ) -> RpcProcessingResult<(), FixedBlobSidecarList<T::EthSpec>> {
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
        Some(((), resp))
    }

    pub fn on_data_columns_by_root_response(
        &mut self,
        id: Id,
        item: RpcEvent<Arc<DataColumnSidecar<T::EthSpec>>>,
    ) -> RpcProcessingResult<DataColumnsByRootRequester, Vec<Arc<DataColumnSidecar<T::EthSpec>>>>
    {
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
        Some((requester, resp))
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
