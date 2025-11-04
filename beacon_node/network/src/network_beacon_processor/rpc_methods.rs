use crate::metrics;
use crate::network_beacon_processor::{FUTURE_SLOT_TOLERANCE, NetworkBeaconProcessor};
use crate::service::NetworkMessage;
use crate::status::ToStatusMessage;
use crate::sync::SyncMessage;
use beacon_chain::{BeaconChainError, BeaconChainTypes, BlockProcessStatus, WhenSlotSkipped};
use itertools::{Itertools, process_results};
use lighthouse_network::rpc::methods::{
    BlobsByRangeRequest, BlobsByRootRequest, DataColumnsByRangeRequest, DataColumnsByRootRequest,
};
use lighthouse_network::rpc::*;
use lighthouse_network::{PeerId, ReportSource, Response, SyncInfo};
use lighthouse_tracing::{
    SPAN_HANDLE_BLOBS_BY_RANGE_REQUEST, SPAN_HANDLE_BLOBS_BY_ROOT_REQUEST,
    SPAN_HANDLE_BLOCKS_BY_RANGE_REQUEST, SPAN_HANDLE_BLOCKS_BY_ROOT_REQUEST,
    SPAN_HANDLE_DATA_COLUMNS_BY_RANGE_REQUEST, SPAN_HANDLE_DATA_COLUMNS_BY_ROOT_REQUEST,
    SPAN_HANDLE_LIGHT_CLIENT_BOOTSTRAP, SPAN_HANDLE_LIGHT_CLIENT_FINALITY_UPDATE,
    SPAN_HANDLE_LIGHT_CLIENT_OPTIMISTIC_UPDATE, SPAN_HANDLE_LIGHT_CLIENT_UPDATES_BY_RANGE,
};
use methods::LightClientUpdatesByRangeRequest;
use slot_clock::SlotClock;
use std::collections::{HashMap, HashSet, hash_map::Entry};
use std::sync::Arc;
use tokio_stream::StreamExt;
use tracing::{Span, debug, error, field, instrument, warn};
use types::blob_sidecar::BlobIdentifier;
use types::{ColumnIndex, Epoch, EthSpec, Hash256, Slot};

impl<T: BeaconChainTypes> NetworkBeaconProcessor<T> {
    /* Auxiliary functions */

    /// Disconnects and ban's a peer, sending a Goodbye request with the associated reason.
    pub fn goodbye_peer(&self, peer_id: PeerId, reason: GoodbyeReason) {
        self.send_network_message(NetworkMessage::GoodbyePeer {
            peer_id,
            reason,
            source: ReportSource::Processor,
        });
    }

    pub fn send_response(
        &self,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        response: Response<T::EthSpec>,
    ) {
        self.send_network_message(NetworkMessage::SendResponse {
            peer_id,
            inbound_request_id,
            response,
        })
    }

    pub fn send_error_response(
        &self,
        peer_id: PeerId,
        error: RpcErrorResponse,
        reason: String,
        inbound_request_id: InboundRequestId,
    ) {
        self.send_network_message(NetworkMessage::SendErrorResponse {
            peer_id,
            error,
            reason,
            inbound_request_id,
        })
    }

    /* Processing functions */

    /// Process a `Status` message to determine if a peer is relevant to us. If the peer is
    /// irrelevant the reason is returned.
    fn check_peer_relevance(
        &self,
        remote: &StatusMessage,
    ) -> Result<Option<String>, Box<BeaconChainError>> {
        let local = self.chain.status_message();
        let start_slot = |epoch: Epoch| epoch.start_slot(T::EthSpec::slots_per_epoch());

        let irrelevant_reason = if local.fork_digest() != remote.fork_digest() {
            // The node is on a different network/fork
            Some(format!(
                "Incompatible forks Ours:{} Theirs:{}",
                hex::encode(local.fork_digest()),
                hex::encode(remote.fork_digest())
            ))
        } else if *remote.head_slot()
            > self
                .chain
                .slot()
                .unwrap_or_else(|_| self.chain.slot_clock.genesis_slot())
                + FUTURE_SLOT_TOLERANCE
        {
            // The remote's head is on a slot that is significantly ahead of what we consider the
            // current slot. This could be because they are using a different genesis time, or that
            // their or our system's clock is incorrect.
            Some("Different system clocks or genesis time".to_string())
        } else if (remote.finalized_epoch() == local.finalized_epoch()
            && remote.finalized_root() == local.finalized_root())
            || remote.finalized_root().is_zero()
            || local.finalized_root().is_zero()
            || remote.finalized_epoch() > local.finalized_epoch()
        {
            // Fast path. Remote finalized checkpoint is either identical, or genesis, or we are at
            // genesis, or they are ahead. In all cases, we should allow this peer to connect to us
            // so we can sync from them.
            None
        } else {
            // Remote finalized epoch is less than ours.
            let remote_finalized_slot = start_slot(*remote.finalized_epoch());
            if remote_finalized_slot < self.chain.store.get_oldest_block_slot() {
                // Peer's finalized checkpoint is older than anything in our DB. We are unlikely
                // to be able to help them sync.
                Some("Old finality out of range".to_string())
            } else if remote_finalized_slot < self.chain.store.get_split_slot() {
                // Peer's finalized slot is in range for a quick block root check in our freezer DB.
                // If that block root check fails, reject them as they're on a different finalized
                // chain.
                if self
                    .chain
                    .block_root_at_slot(remote_finalized_slot, WhenSlotSkipped::Prev)
                    .map(|root_opt| root_opt != Some(*remote.finalized_root()))
                    .map_err(Box::new)?
                {
                    Some("Different finalized chain".to_string())
                } else {
                    None
                }
            } else {
                // Peer's finality is older than ours, but newer than our split point, making a
                // block root check infeasible. This case shouldn't happen particularly often so
                // we give the peer the benefit of the doubt and let them connect to us.
                None
            }
        };

        Ok(irrelevant_reason)
    }

    pub fn process_status(&self, peer_id: PeerId, status: StatusMessage) {
        match self.check_peer_relevance(&status) {
            Ok(Some(irrelevant_reason)) => {
                debug!(%peer_id, reason = irrelevant_reason, "Handshake Failure");
                self.goodbye_peer(peer_id, GoodbyeReason::IrrelevantNetwork);
            }
            Ok(None) => {
                let info = SyncInfo {
                    head_slot: *status.head_slot(),
                    head_root: *status.head_root(),
                    finalized_epoch: *status.finalized_epoch(),
                    finalized_root: *status.finalized_root(),
                    earliest_available_slot: status.earliest_available_slot().ok().cloned(),
                };
                self.send_sync_message(SyncMessage::AddPeer(peer_id, info));
            }
            Err(e) => error!(
                %peer_id,
                error = ?e,
                "Could not process status message"
            ),
        }
    }

    /// Handle a `BlocksByRoot` request from the peer.
    #[instrument(
        name = SPAN_HANDLE_BLOCKS_BY_ROOT_REQUEST,
        parent = None,
        level = "debug",
        skip_all,
        fields(peer_id = %peer_id, client = tracing::field::Empty)
    )]
    pub async fn handle_blocks_by_root_request(
        self: Arc<Self>,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        request: BlocksByRootRequest,
    ) {
        let client = self.network_globals.client(&peer_id);
        Span::current().record("client", field::display(client.kind));

        self.terminate_response_stream(
            peer_id,
            inbound_request_id,
            self.clone()
                .handle_blocks_by_root_request_inner(peer_id, inbound_request_id, request)
                .await,
            Response::BlocksByRoot,
        );
    }

    /// Handle a `BlocksByRoot` request from the peer.
    async fn handle_blocks_by_root_request_inner(
        self: Arc<Self>,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        request: BlocksByRootRequest,
    ) -> Result<(), (RpcErrorResponse, &'static str)> {
        let log_results = |peer_id, requested_blocks, send_block_count| {
            debug!(
                %peer_id,
                requested = requested_blocks,
                returned = %send_block_count,
                "BlocksByRoot outgoing response processed"
            );
        };

        let requested_blocks = request.block_roots().len();
        let mut block_stream = match self
            .chain
            .get_blocks_checking_caches(request.block_roots().to_vec())
        {
            Ok(block_stream) => block_stream,
            Err(e) => {
                error!( error = ?e, "Error getting block stream");
                return Err((RpcErrorResponse::ServerError, "Error getting block stream"));
            }
        };
        // Fetching blocks is async because it may have to hit the execution layer for payloads.
        let mut send_block_count = 0;
        while let Some((root, result)) = block_stream.next().await {
            match result.as_ref() {
                Ok(Some(block)) => {
                    self.send_response(
                        peer_id,
                        inbound_request_id,
                        Response::BlocksByRoot(Some(block.clone())),
                    );
                    send_block_count += 1;
                }
                Ok(None) => {
                    debug!(
                        %peer_id,
                        request_root = ?root,
                        "Peer requested unknown block"
                    );
                }
                Err(BeaconChainError::BlockHashMissingFromExecutionLayer(_)) => {
                    debug!(
                        block_root = ?root,
                        reason = "execution layer not synced",
                        "Failed to fetch execution payload for blocks by root request"
                    );
                    log_results(peer_id, requested_blocks, send_block_count);
                    return Err((
                        RpcErrorResponse::ResourceUnavailable,
                        "Execution layer not synced",
                    ));
                }
                Err(e) => {
                    debug!(
                        ?peer_id,
                        request_root = ?root,
                        error = ?e,
                        "Error fetching block for peer"
                    );
                }
            }
        }
        log_results(peer_id, requested_blocks, send_block_count);

        Ok(())
    }

    /// Handle a `BlobsByRoot` request from the peer.
    #[instrument(
        name = SPAN_HANDLE_BLOBS_BY_ROOT_REQUEST,
        parent = None,
        level = "debug",
        skip_all,
        fields(peer_id = %peer_id, client = tracing::field::Empty)
    )]
    pub fn handle_blobs_by_root_request(
        self: Arc<Self>,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        request: BlobsByRootRequest,
    ) {
        let client = self.network_globals.client(&peer_id);
        Span::current().record("client", field::display(client.kind));

        self.terminate_response_stream(
            peer_id,
            inbound_request_id,
            self.handle_blobs_by_root_request_inner(peer_id, inbound_request_id, request),
            Response::BlobsByRoot,
        );
    }

    /// Handle a `BlobsByRoot` request from the peer.
    fn handle_blobs_by_root_request_inner(
        &self,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        request: BlobsByRootRequest,
    ) -> Result<(), (RpcErrorResponse, &'static str)> {
        let requested_roots: HashSet<Hash256> =
            request.blob_ids.iter().map(|id| id.block_root).collect();

        let mut send_blob_count = 0;

        let fulu_start_slot = self
            .chain
            .spec
            .fulu_fork_epoch
            .map(|epoch| epoch.start_slot(T::EthSpec::slots_per_epoch()));

        let mut blob_list_results = HashMap::new();

        let slots_by_block_root: HashMap<Hash256, Slot> = request
            .blob_ids
            .iter()
            .flat_map(|blob_id| {
                let block_root = blob_id.block_root;
                self.chain
                    .data_availability_checker
                    .get_cached_block(&block_root)
                    .and_then(|status| match status {
                        BlockProcessStatus::NotValidated(block, _source) => Some(block),
                        BlockProcessStatus::ExecutionValidated(block) => Some(block),
                        BlockProcessStatus::Unknown => None,
                    })
                    .or_else(|| self.chain.early_attester_cache.get_block(block_root))
                    .map(|block| (block_root, block.slot()))
            })
            .collect();

        for id in request.blob_ids.as_slice() {
            let BlobIdentifier {
                block_root: root,
                index,
            } = id;

            let slot = slots_by_block_root.get(root);

            // Skip if slot is >= fulu_start_slot
            if let (Some(slot), Some(fulu_slot)) = (slot, fulu_start_slot)
                && *slot >= fulu_slot
            {
                continue;
            }

            // First attempt to get the blobs from the RPC cache.
            if let Ok(Some(blob)) = self.chain.data_availability_checker.get_blob(id) {
                self.send_response(
                    peer_id,
                    inbound_request_id,
                    Response::BlobsByRoot(Some(blob)),
                );
                send_blob_count += 1;
            } else {
                let blob_list_result = match blob_list_results.entry(root) {
                    Entry::Vacant(entry) => {
                        entry.insert(self.chain.get_blobs_checking_early_attester_cache(root))
                    }
                    Entry::Occupied(entry) => entry.into_mut(),
                };

                match blob_list_result.as_ref() {
                    Ok(blobs_sidecar_list) => {
                        if let Some(blob_sidecar) =
                            blobs_sidecar_list.iter().find(|b| b.index == *index)
                        {
                            self.send_response(
                                peer_id,
                                inbound_request_id,
                                Response::BlobsByRoot(Some(blob_sidecar.clone())),
                            );
                            send_blob_count += 1;
                        }
                    }
                    Err(e) => {
                        debug!(
                            ?peer_id,
                            request_root = ?root,
                            error = ?e,
                            "Error fetching blob for peer"
                        );
                    }
                }
            }
        }

        debug!(
            %peer_id,
            ?requested_roots,
            returned = send_blob_count,
            "BlobsByRoot outgoing response processed"
        );

        Ok(())
    }

    /// Handle a `DataColumnsByRoot` request from the peer.
    #[instrument(
        name = SPAN_HANDLE_DATA_COLUMNS_BY_ROOT_REQUEST,
        parent = None,
        level = "debug",
        skip_all,
        fields(
            peer_id = %peer_id,
            client = tracing::field::Empty,
            non_custody_indices = tracing::field::Empty,
        )
    )]
    pub fn handle_data_columns_by_root_request(
        self: Arc<Self>,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        request: DataColumnsByRootRequest<T::EthSpec>,
    ) {
        let requested_columns = request
            .data_column_ids
            .iter()
            .flat_map(|id| id.columns.clone())
            .unique()
            .collect::<Vec<_>>();
        self.record_data_column_request_in_span(
            &peer_id,
            &requested_columns,
            None,
            Span::current(),
        );

        self.terminate_response_stream(
            peer_id,
            inbound_request_id,
            self.handle_data_columns_by_root_request_inner(peer_id, inbound_request_id, request),
            Response::DataColumnsByRoot,
        );
    }

    /// Handle a `DataColumnsByRoot` request from the peer.
    fn handle_data_columns_by_root_request_inner(
        &self,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        request: DataColumnsByRootRequest<T::EthSpec>,
    ) -> Result<(), (RpcErrorResponse, &'static str)> {
        let mut send_data_column_count = 0;
        // Only attempt lookups for columns the node has advertised and is responsible for maintaining custody of.
        let available_columns = self.chain.custody_columns_for_epoch(None);

        for data_column_ids_by_root in request.data_column_ids.as_slice() {
            let indices_to_retrieve = data_column_ids_by_root
                .columns
                .iter()
                .copied()
                .filter(|c| available_columns.contains(c))
                .collect::<Vec<_>>();
            match self.chain.get_data_columns_checking_all_caches(
                data_column_ids_by_root.block_root,
                &indices_to_retrieve,
            ) {
                Ok(data_columns) => {
                    send_data_column_count += data_columns.len();
                    for data_column in data_columns {
                        self.send_response(
                            peer_id,
                            inbound_request_id,
                            Response::DataColumnsByRoot(Some(data_column)),
                        );
                    }
                }
                Err(e) => {
                    // The node is expected to be able to serve these columns, but it fails to retrieve them.
                    warn!(
                        block_root = ?data_column_ids_by_root.block_root,
                        %peer_id,
                        error = ?e,
                        "Error getting data column for by root request "
                    );
                    return Err((RpcErrorResponse::ServerError, "Error getting data column"));
                }
            }
        }

        debug!(
            %peer_id,
            request = ?request.data_column_ids,
            returned = send_data_column_count,
            "Received DataColumnsByRoot Request"
        );

        Ok(())
    }

    #[instrument(
        name = SPAN_HANDLE_LIGHT_CLIENT_UPDATES_BY_RANGE,
        parent = None,
        level = "debug",
        skip_all,
        fields(peer_id = %peer_id, client = tracing::field::Empty)
    )]
    pub fn handle_light_client_updates_by_range(
        self: &Arc<Self>,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        request: LightClientUpdatesByRangeRequest,
    ) {
        let client = self.network_globals.client(&peer_id);
        Span::current().record("client", field::display(client.kind));

        self.terminate_response_stream(
            peer_id,
            inbound_request_id,
            self.clone()
                .handle_light_client_updates_by_range_request_inner(
                    peer_id,
                    inbound_request_id,
                    request,
                ),
            Response::LightClientUpdatesByRange,
        );
    }

    /// Handle a `LightClientUpdatesByRange` request from the peer.
    fn handle_light_client_updates_by_range_request_inner(
        self: Arc<Self>,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        req: LightClientUpdatesByRangeRequest,
    ) -> Result<(), (RpcErrorResponse, &'static str)> {
        debug!(
            %peer_id,
            count = req.count,
            start_period = req.start_period,
            "Received LightClientUpdatesByRange Request"
        );

        // Should not send more than max light client updates
        let max_request_size: u64 = req.max_requested();
        if req.count > max_request_size {
            return Err((
                RpcErrorResponse::InvalidRequest,
                "Request exceeded max size",
            ));
        }

        let lc_updates = match self
            .chain
            .get_light_client_updates(req.start_period, req.count)
        {
            Ok(lc_updates) => lc_updates,
            Err(e) => {
                error!(
                    request = ?req,
                    peer = %peer_id,
                    error = ?e,
                    "Unable to obtain light client updates"
                );
                return Err((RpcErrorResponse::ServerError, "Database error"));
            }
        };

        for lc_update in lc_updates.iter() {
            self.send_network_message(NetworkMessage::SendResponse {
                peer_id,
                response: Response::LightClientUpdatesByRange(Some(Arc::new(lc_update.clone()))),
                inbound_request_id,
            });
        }

        let lc_updates_sent = lc_updates.len();

        if lc_updates_sent < req.count as usize {
            debug!(
                peer = %peer_id,
                info = "Failed to return all requested light client updates. The peer may have requested data ahead of whats currently available",
                start_period = req.start_period,
                requested = req.count,
                returned = lc_updates_sent,
                "LightClientUpdatesByRange outgoing response processed"
            );
        } else {
            debug!(
                peer = %peer_id,
                start_period = req.start_period,
                requested = req.count,
                returned = lc_updates_sent,
                "LightClientUpdatesByRange outgoing response processed"
            );
        }

        Ok(())
    }

    /// Handle a `LightClientBootstrap` request from the peer.
    #[instrument(
        name = SPAN_HANDLE_LIGHT_CLIENT_BOOTSTRAP,
        parent = None,
        level = "debug",
        skip_all,
        fields(peer_id = %peer_id, client = tracing::field::Empty)
    )]
    pub fn handle_light_client_bootstrap(
        self: &Arc<Self>,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        request: LightClientBootstrapRequest,
    ) {
        let client = self.network_globals.client(&peer_id);
        Span::current().record("client", field::display(client.kind));

        self.terminate_response_single_item(
            peer_id,
            inbound_request_id,
            match self.chain.get_light_client_bootstrap(&request.root) {
                Ok(Some((bootstrap, _))) => Ok(Arc::new(bootstrap)),
                Ok(None) => Err((
                    RpcErrorResponse::ResourceUnavailable,
                    "Bootstrap not available".to_string(),
                )),
                Err(e) => {
                    error!(
                        block_root = ?request.root,
                        %peer_id,
                        error = ?e,
                        "Error getting LightClientBootstrap instance"
                    );
                    Err((RpcErrorResponse::ResourceUnavailable, format!("{:?}", e)))
                }
            },
            Response::LightClientBootstrap,
        );
    }

    /// Handle a `LightClientOptimisticUpdate` request from the peer.
    #[instrument(
        name = SPAN_HANDLE_LIGHT_CLIENT_OPTIMISTIC_UPDATE,
        parent = None,
        level = "debug",
        skip_all,
        fields(peer_id = %peer_id, client = tracing::field::Empty)
    )]
    pub fn handle_light_client_optimistic_update(
        self: &Arc<Self>,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
    ) {
        let client = self.network_globals.client(&peer_id);
        Span::current().record("client", field::display(client.kind));

        self.terminate_response_single_item(
            peer_id,
            inbound_request_id,
            match self
                .chain
                .light_client_server_cache
                .get_latest_optimistic_update()
            {
                Some(update) => Ok(Arc::new(update)),
                None => Err((
                    RpcErrorResponse::ResourceUnavailable,
                    "Latest optimistic update not available".to_string(),
                )),
            },
            Response::LightClientOptimisticUpdate,
        );
    }

    /// Handle a `LightClientFinalityUpdate` request from the peer.
    #[instrument(
        name = SPAN_HANDLE_LIGHT_CLIENT_FINALITY_UPDATE,
        parent = None,
        level = "debug",
        skip_all,
        fields(peer_id = %peer_id, client = tracing::field::Empty)
    )]
    pub fn handle_light_client_finality_update(
        self: &Arc<Self>,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
    ) {
        let client = self.network_globals.client(&peer_id);
        Span::current().record("client", field::display(client.kind));

        self.terminate_response_single_item(
            peer_id,
            inbound_request_id,
            match self
                .chain
                .light_client_server_cache
                .get_latest_finality_update()
            {
                Some(update) => Ok(Arc::new(update)),
                None => Err((
                    RpcErrorResponse::ResourceUnavailable,
                    "Latest finality update not available".to_string(),
                )),
            },
            Response::LightClientFinalityUpdate,
        );
    }

    /// Handle a `BlocksByRange` request from the peer.
    #[instrument(
        name = SPAN_HANDLE_BLOCKS_BY_RANGE_REQUEST,
        parent = None,
        level = "debug",
        skip_all,
        fields(peer_id = %peer_id, client = tracing::field::Empty)
    )]
    pub async fn handle_blocks_by_range_request(
        self: Arc<Self>,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        req: BlocksByRangeRequest,
    ) {
        let client = self.network_globals.client(&peer_id);
        Span::current().record("client", field::display(client.kind));

        self.terminate_response_stream(
            peer_id,
            inbound_request_id,
            self.clone()
                .handle_blocks_by_range_request_inner(peer_id, inbound_request_id, req)
                .await,
            Response::BlocksByRange,
        );
    }

    /// Handle a `BlocksByRange` request from the peer.
    async fn handle_blocks_by_range_request_inner(
        self: Arc<Self>,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        req: BlocksByRangeRequest,
    ) -> Result<(), (RpcErrorResponse, &'static str)> {
        let req_start_slot = *req.start_slot();
        let req_count = *req.count();

        debug!(
            %peer_id,
            count = req_count,
            start_slot = %req_start_slot,
            "Received BlocksByRange Request"
        );

        // Spawn a blocking handle since get_block_roots_for_slot_range takes a sync lock on the
        // fork-choice.
        let network_beacon_processor = self.clone();
        let block_roots = self
            .executor
            .spawn_blocking_handle(
                move || {
                    network_beacon_processor.get_block_roots_for_slot_range(
                        req_start_slot,
                        req_count,
                        "BlocksByRange",
                    )
                },
                "get_block_roots_for_slot_range",
            )
            .ok_or((RpcErrorResponse::ServerError, "shutting down"))?
            .await
            .map_err(|_| (RpcErrorResponse::ServerError, "tokio join"))??;

        let current_slot = self
            .chain
            .slot()
            .unwrap_or_else(|_| self.chain.slot_clock.genesis_slot());

        let log_results = |peer_id, blocks_sent| {
            if blocks_sent < (req_count as usize) {
                debug!(
                    %peer_id,
                    msg = "Failed to return all requested blocks",
                    start_slot = %req_start_slot,
                    %current_slot,
                    requested = req_count,
                    returned = blocks_sent,
                    "BlocksByRange outgoing response processed"
                );
            } else {
                debug!(
                    %peer_id,
                    start_slot = %req_start_slot,
                    %current_slot,
                    requested = req_count,
                    returned = blocks_sent,
                    "BlocksByRange outgoing response processed"
                );
            }
        };

        let mut block_stream = match self.chain.get_blocks(block_roots) {
            Ok(block_stream) => block_stream,
            Err(e) => {
                error!(error = ?e, "Error getting block stream");
                return Err((RpcErrorResponse::ServerError, "Iterator error"));
            }
        };

        // Fetching blocks is async because it may have to hit the execution layer for payloads.
        let mut blocks_sent = 0;
        while let Some((root, result)) = block_stream.next().await {
            match result.as_ref() {
                Ok(Some(block)) => {
                    // Due to skip slots, blocks could be out of the range, we ensure they
                    // are in the range before sending
                    if block.slot() >= req_start_slot && block.slot() < req_start_slot + req.count()
                    {
                        blocks_sent += 1;
                        self.send_network_message(NetworkMessage::SendResponse {
                            peer_id,
                            inbound_request_id,
                            response: Response::BlocksByRange(Some(block.clone())),
                        });
                    }
                }
                Ok(None) => {
                    error!(
                        request = ?req,
                        %peer_id,
                        request_root = ?root,
                        "Block in the chain is not in the store"
                    );
                    log_results(peer_id, blocks_sent);
                    return Err((RpcErrorResponse::ServerError, "Database inconsistency"));
                }
                Err(BeaconChainError::BlockHashMissingFromExecutionLayer(_)) => {
                    debug!(
                        block_root = ?root,
                        reason = "execution layer not synced",
                        "Failed to fetch execution payload for blocks by range request"
                    );
                    log_results(peer_id, blocks_sent);
                    // send the stream terminator
                    return Err((
                        RpcErrorResponse::ResourceUnavailable,
                        "Execution layer not synced",
                    ));
                }
                Err(e) => {
                    if matches!(
                        e,
                        BeaconChainError::ExecutionLayerErrorPayloadReconstruction(_block_hash, boxed_error)
                        if matches!(**boxed_error, execution_layer::Error::EngineError(_))
                    ) {
                        warn!(
                            info = "this may occur occasionally when the EE is busy",
                            block_root = ?root,
                            error = ?e,
                            "Error rebuilding payload for peer"
                        );
                    } else {
                        error!(
                            block_root = ?root,
                            error = ?e,
                            "Error fetching block for peer"
                        );
                    }
                    log_results(peer_id, blocks_sent);
                    // send the stream terminator
                    return Err((RpcErrorResponse::ServerError, "Failed fetching blocks"));
                }
            }
        }

        log_results(peer_id, blocks_sent);
        Ok(())
    }

    fn get_block_roots_for_slot_range(
        &self,
        req_start_slot: u64,
        req_count: u64,
        req_type: &str,
    ) -> Result<Vec<Hash256>, (RpcErrorResponse, &'static str)> {
        let start_time = std::time::Instant::now();
        let finalized_slot = self
            .chain
            .canonical_head
            .cached_head()
            .finalized_checkpoint()
            .epoch
            .start_slot(T::EthSpec::slots_per_epoch());

        let (block_roots, source) = if req_start_slot >= finalized_slot.as_u64() {
            // If the entire requested range is after finalization, use fork_choice
            (
                self.chain
                    .block_roots_from_fork_choice(req_start_slot, req_count),
                "fork_choice",
            )
        } else if req_start_slot + req_count <= finalized_slot.as_u64() {
            // If the entire requested range is before finalization, use store
            (
                self.get_block_roots_from_store(req_start_slot, req_count)?,
                "store",
            )
        } else {
            // Split the request at the finalization boundary
            let count_from_store = finalized_slot.as_u64() - req_start_slot;
            let count_from_fork_choice = req_count - count_from_store;
            let start_slot_fork_choice = finalized_slot.as_u64();

            // Get roots from store (up to and including finalized slot)
            let mut roots_from_store =
                self.get_block_roots_from_store(req_start_slot, count_from_store)?;

            // Get roots from fork choice (after finalized slot)
            let roots_from_fork_choice = self
                .chain
                .block_roots_from_fork_choice(start_slot_fork_choice, count_from_fork_choice);

            roots_from_store.extend(roots_from_fork_choice);

            (roots_from_store, "mixed")
        };

        let elapsed = start_time.elapsed();
        metrics::observe_timer_vec(
            &metrics::BEACON_PROCESSOR_GET_BLOCK_ROOTS_TIME,
            &[source],
            elapsed,
        );

        debug!(
            req_type,
            start_slot = %req_start_slot,
            req_count,
            roots_count = block_roots.len(),
            source,
            elapsed = ?elapsed,
            %finalized_slot,
            "Range request block roots retrieved"
        );

        Ok(block_roots)
    }

    /// Get block roots for a `BlocksByRangeRequest` from the store using roots iterator.
    fn get_block_roots_from_store(
        &self,
        start_slot: u64,
        count: u64,
    ) -> Result<Vec<Hash256>, (RpcErrorResponse, &'static str)> {
        let forwards_block_root_iter =
            match self.chain.forwards_iter_block_roots(Slot::from(start_slot)) {
                Ok(iter) => iter,
                Err(BeaconChainError::HistoricalBlockOutOfRange {
                    slot,
                    oldest_block_slot,
                }) => {
                    debug!(
                        requested_slot = %slot,
                        oldest_known_slot = %oldest_block_slot,
                        "Range request failed during backfill"
                    );
                    return Err((RpcErrorResponse::ResourceUnavailable, "Backfilling"));
                }
                Err(e) => {
                    error!(
                        %start_slot,
                        count,
                        error = ?e,
                        "Unable to obtain root iter for range request"
                    );
                    return Err((RpcErrorResponse::ServerError, "Database error"));
                }
            };

        // Pick out the required blocks, ignoring skip-slots.
        let maybe_block_roots = process_results(forwards_block_root_iter, |iter| {
            iter.take_while(|(_, slot)| slot.as_u64() < start_slot.saturating_add(count))
                .collect::<Vec<_>>()
        });

        let block_roots = match maybe_block_roots {
            Ok(block_roots) => block_roots,
            Err(e) => {
                error!(
                    %start_slot,
                    count,
                    error = ?e,
                    "Error during iteration over blocks for range request"
                );
                return Err((RpcErrorResponse::ServerError, "Iteration error"));
            }
        };

        // remove all skip slots i.e. duplicated roots
        Ok(block_roots
            .into_iter()
            .map(|(root, _)| root)
            .unique()
            .collect::<Vec<_>>())
    }

    /// Handle a `BlobsByRange` request from the peer.
    #[instrument(
        name = SPAN_HANDLE_BLOBS_BY_RANGE_REQUEST,
        parent = None,
        skip_all,
        level = "debug",
        fields(peer_id = %peer_id, client = tracing::field::Empty)
    )]
    pub fn handle_blobs_by_range_request(
        self: Arc<Self>,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        req: BlobsByRangeRequest,
    ) {
        let client = self.network_globals.client(&peer_id);
        Span::current().record("client", field::display(client.kind));

        self.terminate_response_stream(
            peer_id,
            inbound_request_id,
            self.handle_blobs_by_range_request_inner(peer_id, inbound_request_id, req),
            Response::BlobsByRange,
        );
    }

    /// Handle a `BlobsByRange` request from the peer.
    fn handle_blobs_by_range_request_inner(
        &self,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        req: BlobsByRangeRequest,
    ) -> Result<(), (RpcErrorResponse, &'static str)> {
        debug!(
            ?peer_id,
            count = req.count,
            start_slot = req.start_slot,
            "Received BlobsByRange Request"
        );

        let request_start_slot = Slot::from(req.start_slot);
        let request_start_epoch = request_start_slot.epoch(T::EthSpec::slots_per_epoch());
        let fork_name = self.chain.spec.fork_name_at_epoch(request_start_epoch);
        // Should not send more than max request blob sidecars
        if req.max_blobs_requested(request_start_epoch, &self.chain.spec)
            > self.chain.spec.max_request_blob_sidecars(fork_name) as u64
        {
            return Err((
                RpcErrorResponse::InvalidRequest,
                "Request exceeded `MAX_REQUEST_BLOBS_SIDECARS`",
            ));
        }

        let effective_count = if let Some(fulu_epoch) = self.chain.spec.fulu_fork_epoch {
            let fulu_start_slot = fulu_epoch.start_slot(T::EthSpec::slots_per_epoch());
            let request_end_slot = request_start_slot.saturating_add(req.count) - 1;

            // If the request_start_slot is at or after a Fulu slot, return an empty response
            if request_start_slot >= fulu_start_slot {
                return Ok(());
            // For the case that the request slots spans across the Fulu fork slot
            } else if request_end_slot >= fulu_start_slot {
                (fulu_start_slot - request_start_slot).as_u64()
            } else {
                req.count
            }
        } else {
            req.count
        };

        let data_availability_boundary_slot = match self.chain.data_availability_boundary() {
            Some(boundary) => boundary.start_slot(T::EthSpec::slots_per_epoch()),
            None => {
                debug!("Deneb fork is disabled");
                return Err((RpcErrorResponse::InvalidRequest, "Deneb fork is disabled"));
            }
        };

        let oldest_blob_slot = self
            .chain
            .store
            .get_blob_info()
            .oldest_blob_slot
            .unwrap_or(data_availability_boundary_slot);
        if request_start_slot < oldest_blob_slot {
            debug!(
                %request_start_slot,
                %oldest_blob_slot,
                %data_availability_boundary_slot,
                "Range request start slot is older than data availability boundary."
            );

            return if data_availability_boundary_slot < oldest_blob_slot {
                Err((
                    RpcErrorResponse::ResourceUnavailable,
                    "blobs pruned within boundary",
                ))
            } else {
                Err((
                    RpcErrorResponse::InvalidRequest,
                    "Req outside availability period",
                ))
            };
        }

        let block_roots =
            self.get_block_roots_for_slot_range(req.start_slot, effective_count, "BlobsByRange")?;

        let current_slot = self
            .chain
            .slot()
            .unwrap_or_else(|_| self.chain.slot_clock.genesis_slot());

        let log_results = |peer_id, req: BlobsByRangeRequest, blobs_sent| {
            debug!(
                %peer_id,
                start_slot = req.start_slot,
                %current_slot,
                requested = req.count,
                returned = blobs_sent,
                "BlobsByRange outgoing response processed"
            );
        };

        let mut blobs_sent = 0;

        for root in block_roots {
            match self.chain.get_blobs(&root) {
                Ok(blob_sidecar_list) => {
                    for blob_sidecar in blob_sidecar_list.iter() {
                        // Due to skip slots, blobs could be out of the range, we ensure they
                        // are in the range before sending
                        if blob_sidecar.slot() >= request_start_slot
                            && blob_sidecar.slot() < request_start_slot + effective_count
                        {
                            blobs_sent += 1;
                            self.send_network_message(NetworkMessage::SendResponse {
                                peer_id,
                                inbound_request_id,
                                response: Response::BlobsByRange(Some(blob_sidecar.clone())),
                            });
                        }
                    }
                }
                Err(e) => {
                    error!(
                        request = ?req,
                        %peer_id,
                        block_root = ?root,
                        error = ?e,
                        "Error fetching blobs block root"
                    );
                    log_results(peer_id, req, blobs_sent);

                    return Err((
                        RpcErrorResponse::ServerError,
                        "No blobs and failed fetching corresponding block",
                    ));
                }
            }
        }
        log_results(peer_id, req, blobs_sent);

        Ok(())
    }

    /// Handle a `DataColumnsByRange` request from the peer.
    #[instrument(
        name = SPAN_HANDLE_DATA_COLUMNS_BY_RANGE_REQUEST,
        parent = None,
        skip_all,
        level = "debug",
        fields(peer_id = %peer_id, non_custody_indices = tracing::field::Empty, client = tracing::field::Empty)
    )]
    pub fn handle_data_columns_by_range_request(
        &self,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        req: DataColumnsByRangeRequest,
    ) {
        let epoch = Slot::new(req.start_slot).epoch(T::EthSpec::slots_per_epoch());
        self.record_data_column_request_in_span(
            &peer_id,
            &req.columns,
            Some(epoch),
            Span::current(),
        );

        self.terminate_response_stream(
            peer_id,
            inbound_request_id,
            self.handle_data_columns_by_range_request_inner(peer_id, inbound_request_id, req),
            Response::DataColumnsByRange,
        );
    }

    /// Handle a `DataColumnsByRange` request from the peer.
    fn handle_data_columns_by_range_request_inner(
        &self,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        req: DataColumnsByRangeRequest,
    ) -> Result<(), (RpcErrorResponse, &'static str)> {
        debug!(
            %peer_id,
            count = req.count,
            start_slot = req.start_slot,
            "Received DataColumnsByRange Request"
        );

        // Should not send more than max request data columns
        if req.max_requested::<T::EthSpec>() > self.chain.spec.max_request_data_column_sidecars {
            return Err((
                RpcErrorResponse::InvalidRequest,
                "Request exceeded `MAX_REQUEST_DATA_COLUMN_SIDECARS`",
            ));
        }

        let request_start_slot = Slot::from(req.start_slot);

        let column_data_availability_boundary_slot =
            match self.chain.column_data_availability_boundary() {
                Some(boundary) => boundary.start_slot(T::EthSpec::slots_per_epoch()),
                None => {
                    debug!("Fulu fork is disabled");
                    return Err((RpcErrorResponse::InvalidRequest, "Fulu fork is disabled"));
                }
            };

        let earliest_custodied_data_column_slot =
            match self.chain.earliest_custodied_data_column_epoch() {
                Some(earliest_custodied_epoch) => {
                    let earliest_custodied_slot =
                        earliest_custodied_epoch.start_slot(T::EthSpec::slots_per_epoch());
                    // Ensure the earliest columns we serve are within the data availability window
                    if earliest_custodied_slot < column_data_availability_boundary_slot {
                        column_data_availability_boundary_slot
                    } else {
                        earliest_custodied_slot
                    }
                }
                None => column_data_availability_boundary_slot,
            };

        if request_start_slot < earliest_custodied_data_column_slot {
            debug!(
                %request_start_slot,
                %earliest_custodied_data_column_slot,
                %column_data_availability_boundary_slot,
                "Range request start slot is older than the earliest custodied data column slot."
            );

            return if earliest_custodied_data_column_slot > column_data_availability_boundary_slot {
                Err((
                    RpcErrorResponse::ResourceUnavailable,
                    "columns pruned within boundary",
                ))
            } else {
                Err((
                    RpcErrorResponse::InvalidRequest,
                    "Req outside availability period",
                ))
            };
        }

        let block_roots =
            self.get_block_roots_for_slot_range(req.start_slot, req.count, "DataColumnsByRange")?;
        let mut data_columns_sent = 0;

        // Only attempt lookups for columns the node has advertised and is responsible for maintaining custody of.
        let request_start_epoch = request_start_slot.epoch(T::EthSpec::slots_per_epoch());
        let available_columns = self
            .chain
            .custody_columns_for_epoch(Some(request_start_epoch));

        let indices_to_retrieve = req
            .columns
            .iter()
            .copied()
            .filter(|c| available_columns.contains(c))
            .collect::<Vec<_>>();

        for root in block_roots {
            for index in &indices_to_retrieve {
                match self.chain.get_data_column(&root, index) {
                    Ok(Some(data_column_sidecar)) => {
                        // Due to skip slots, data columns could be out of the range, we ensure they
                        // are in the range before sending
                        if data_column_sidecar.slot() >= request_start_slot
                            && data_column_sidecar.slot() < request_start_slot + req.count
                        {
                            data_columns_sent += 1;
                            self.send_network_message(NetworkMessage::SendResponse {
                                peer_id,
                                inbound_request_id,
                                response: Response::DataColumnsByRange(Some(
                                    data_column_sidecar.clone(),
                                )),
                            });
                        }
                    }
                    Ok(None) => {} // no-op
                    Err(e) => {
                        error!(
                            request = ?req,
                            %peer_id,
                            block_root = ?root,
                            error = ?e,
                            "Error fetching data columns block root"
                        );
                        return Err((
                            RpcErrorResponse::ServerError,
                            "No data columns and failed fetching corresponding block",
                        ));
                    }
                }
            }
        }

        let current_slot = self
            .chain
            .slot()
            .unwrap_or_else(|_| self.chain.slot_clock.genesis_slot());

        debug!(
            %peer_id,
            start_slot = req.start_slot,
            %current_slot,
            requested = req.count,
            returned = data_columns_sent,
            "DataColumnsByRange Response processed"
        );

        Ok(())
    }

    /// Helper function to ensure single item protocol always end with either a single chunk or an
    /// error
    fn terminate_response_single_item<R, F: Fn(R) -> Response<T::EthSpec>>(
        &self,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        result: Result<R, (RpcErrorResponse, String)>,
        into_response: F,
    ) {
        match result {
            Ok(resp) => {
                self.send_network_message(NetworkMessage::SendResponse {
                    peer_id,
                    inbound_request_id,
                    response: into_response(resp),
                });
            }
            Err((error_code, reason)) => {
                self.send_error_response(peer_id, error_code, reason, inbound_request_id);
            }
        }
    }

    /// Helper function to ensure streamed protocols with multiple responses always end with either
    /// a stream termination or an error
    fn terminate_response_stream<R, F: FnOnce(Option<R>) -> Response<T::EthSpec>>(
        &self,
        peer_id: PeerId,
        inbound_request_id: InboundRequestId,
        result: Result<(), (RpcErrorResponse, &'static str)>,
        into_response: F,
    ) {
        match result {
            Ok(_) => self.send_network_message(NetworkMessage::SendResponse {
                peer_id,
                inbound_request_id,
                response: into_response(None),
            }),
            Err((error_code, reason)) => {
                self.send_error_response(peer_id, error_code, reason.into(), inbound_request_id);
            }
        }
    }

    fn record_data_column_request_in_span(
        &self,
        peer_id: &PeerId,
        requested_indices: &[ColumnIndex],
        epoch_opt: Option<Epoch>,
        span: Span,
    ) {
        let non_custody_indices = {
            let custody_columns = self
                .chain
                .data_availability_checker
                .custody_context()
                .custody_columns_for_epoch(epoch_opt, &self.chain.spec);
            requested_indices
                .iter()
                .filter(|subnet_id| !custody_columns.contains(subnet_id))
                .collect::<Vec<_>>()
        };
        // This field is used to identify if peers are sending requests on columns we don't custody.
        span.record("non_custody_indices", field::debug(non_custody_indices));

        let client = self.network_globals.client(peer_id);
        span.record("client", field::display(client.kind));
    }
}
