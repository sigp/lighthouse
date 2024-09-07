use crate::network_beacon_processor::{NetworkBeaconProcessor, FUTURE_SLOT_TOLERANCE};
use crate::service::NetworkMessage;
use crate::status::ToStatusMessage;
use crate::sync::SyncMessage;
use beacon_chain::{BeaconChainError, BeaconChainTypes, HistoricalBlockError, WhenSlotSkipped};
use itertools::process_results;
use lighthouse_network::rpc::methods::{
    BlobsByRangeRequest, BlobsByRootRequest, DataColumnsByRangeRequest, DataColumnsByRootRequest,
};
use lighthouse_network::rpc::*;
use lighthouse_network::{PeerId, PeerRequestId, ReportSource, Response, SyncInfo};
use tracing::{debug, error, warn};
use slot_clock::SlotClock;
use std::collections::{hash_map::Entry, HashMap};
use std::sync::Arc;
use tokio_stream::StreamExt;
use types::blob_sidecar::BlobIdentifier;
use types::{Epoch, EthSpec, FixedBytesExtended, ForkName, Hash256, Slot};

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
        response: Response<T::EthSpec>,
        id: PeerRequestId,
    ) {
        self.send_network_message(NetworkMessage::SendResponse {
            peer_id,
            id,
            response,
        })
    }

    pub fn send_error_response(
        &self,
        peer_id: PeerId,
        error: RPCResponseErrorCode,
        reason: String,
        id: PeerRequestId,
    ) {
        self.send_network_message(NetworkMessage::SendErrorResponse {
            peer_id,
            error,
            reason,
            id,
        })
    }

    /* Processing functions */

    /// Process a `Status` message to determine if a peer is relevant to us. If the peer is
    /// irrelevant the reason is returned.
    fn check_peer_relevance(
        &self,
        remote: &StatusMessage,
    ) -> Result<Option<String>, BeaconChainError> {
        let local = self.chain.status_message();
        let start_slot = |epoch: Epoch| epoch.start_slot(T::EthSpec::slots_per_epoch());

        let irrelevant_reason = if local.fork_digest != remote.fork_digest {
            // The node is on a different network/fork
            Some(format!(
                "Incompatible forks Ours:{} Theirs:{}",
                hex::encode(local.fork_digest),
                hex::encode(remote.fork_digest)
            ))
        } else if remote.head_slot
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
        } else if remote.finalized_epoch <= local.finalized_epoch
            && remote.finalized_root != Hash256::zero()
            && local.finalized_root != Hash256::zero()
            && self
                .chain
                .block_root_at_slot(start_slot(remote.finalized_epoch), WhenSlotSkipped::Prev)
                .map(|root_opt| root_opt != Some(remote.finalized_root))?
        {
            // The remote's finalized epoch is less than or equal to ours, but the block root is
            // different to the one in our chain. Therefore, the node is on a different chain and we
            // should not communicate with them.
            Some("Different finalized chain".to_string())
        } else {
            None
        };

        Ok(irrelevant_reason)
    }

    pub fn process_status(&self, peer_id: PeerId, status: StatusMessage) {
        match self.check_peer_relevance(&status) {
            Ok(Some(irrelevant_reason)) => {
                debug!(?peer_id, reason = irrelevant_reason, "Handshake Failure");
                self.goodbye_peer(peer_id, GoodbyeReason::IrrelevantNetwork);
            }
            Ok(None) => {
                let info = SyncInfo {
                    head_slot: status.head_slot,
                    head_root: status.head_root,
                    finalized_epoch: status.finalized_epoch,
                    finalized_root: status.finalized_root,
                };
                self.send_sync_message(SyncMessage::AddPeer(peer_id, info));
            }
            Err(e) => error!(
                ?peer_id,
                error = ?e,
                "Could not process status message"
            ),
        }
    }

    /// Handle a `BlocksByRoot` request from the peer.
    pub async fn handle_blocks_by_root_request(
        self: Arc<Self>,
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: BlocksByRootRequest,
    ) {
        self.terminate_response_stream(
            peer_id,
            request_id,
            self.clone()
                .handle_blocks_by_root_request_inner(peer_id, request_id, request)
                .await,
            Response::BlocksByRoot,
        );
    }

    /// Handle a `BlocksByRoot` request from the peer.
    pub async fn handle_blocks_by_root_request_inner(
        self: Arc<Self>,
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: BlocksByRootRequest,
    ) -> Result<(), (RPCResponseErrorCode, &'static str)> {
        let log_results = |peer_id, requested_blocks, send_block_count| {
            debug!(
                ?peer_id,
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
                return Err((
                    RPCResponseErrorCode::ServerError,
                    "Error getting block stream",
                ));
            }
        };
        // Fetching blocks is async because it may have to hit the execution layer for payloads.
        let mut send_block_count = 0;
        while let Some((root, result)) = block_stream.next().await {
            match result.as_ref() {
                Ok(Some(block)) => {
                    self.send_response(
                        peer_id,
                        Response::BlocksByRoot(Some(block.clone())),
                        request_id,
                    );
                    send_block_count += 1;
                }
                Ok(None) => {
                    debug!(
                        ?peer_id,
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
                        RPCResponseErrorCode::ResourceUnavailable,
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
    pub fn handle_blobs_by_root_request(
        self: Arc<Self>,
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: BlobsByRootRequest,
    ) {
        self.terminate_response_stream(
            peer_id,
            request_id,
            self.handle_blobs_by_root_request_inner(peer_id, request_id, request),
            Response::BlobsByRoot,
        );
    }

    /// Handle a `BlobsByRoot` request from the peer.
    pub fn handle_blobs_by_root_request_inner(
        &self,
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: BlobsByRootRequest,
    ) -> Result<(), (RPCResponseErrorCode, &'static str)> {
        let Some(requested_root) = request.blob_ids.as_slice().first().map(|id| id.block_root)
        else {
            // No blob ids requested.
            return Ok(());
        };
        let requested_indices = request
            .blob_ids
            .as_slice()
            .iter()
            .map(|id| id.index)
            .collect::<Vec<_>>();
        let mut send_blob_count = 0;

        let mut blob_list_results = HashMap::new();
        for id in request.blob_ids.as_slice() {
            // First attempt to get the blobs from the RPC cache.
            if let Ok(Some(blob)) = self.chain.data_availability_checker.get_blob(id) {
                self.send_response(peer_id, Response::BlobsByRoot(Some(blob)), request_id);
                send_blob_count += 1;
            } else {
                let BlobIdentifier {
                    block_root: root,
                    index,
                } = id;

                let blob_list_result = match blob_list_results.entry(root) {
                    Entry::Vacant(entry) => {
                        entry.insert(self.chain.get_blobs_checking_early_attester_cache(root))
                    }
                    Entry::Occupied(entry) => entry.into_mut(),
                };

                match blob_list_result.as_ref() {
                    Ok(blobs_sidecar_list) => {
                        'inner: for blob_sidecar in blobs_sidecar_list.iter() {
                            if blob_sidecar.index == *index {
                                self.send_response(
                                    peer_id,
                                    Response::BlobsByRoot(Some(blob_sidecar.clone())),
                                    request_id,
                                );
                                send_blob_count += 1;
                                break 'inner;
                            }
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
            ?peer_id,
            %requested_root,
            ?requested_indices,
            returned = send_blob_count,
            "BlobsByRoot outgoing response processed"
        );

        Ok(())
    }

    /// Handle a `DataColumnsByRoot` request from the peer.
    pub fn handle_data_columns_by_root_request(
        self: Arc<Self>,
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: DataColumnsByRootRequest,
    ) {
        self.terminate_response_stream(
            peer_id,
            request_id,
            self.handle_data_columns_by_root_request_inner(peer_id, request_id, request),
            Response::DataColumnsByRoot,
        );
    }

    /// Handle a `DataColumnsByRoot` request from the peer.
    pub fn handle_data_columns_by_root_request_inner(
        &self,
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: DataColumnsByRootRequest,
    ) -> Result<(), (RPCResponseErrorCode, &'static str)> {
        let mut send_data_column_count = 0;

        for data_column_id in request.data_column_ids.as_slice() {
            match self.chain.get_data_column_checking_all_caches(
                data_column_id.block_root,
                data_column_id.index,
            ) {
                Ok(Some(data_column)) => {
                    send_data_column_count += 1;
                    self.send_response(
                        peer_id,
                        Response::DataColumnsByRoot(Some(data_column)),
                        request_id,
                    );
                }
                Ok(None) => {} // no-op
                Err(e) => {
                    // TODO(das): lower log level when feature is stabilized
                    error!(
                        block_root = ?data_column_id.block_root,
                        ?peer_id,
                        error = ?e,
                        "Error getting data column"
                    );
                    return Err((
                        RPCResponseErrorCode::ServerError,
                        "Error getting data column",
                    ));
                }
            }
        }

        debug!(
            ?peer_id,
            request = ?request.group_by_ordered_block_root(),
            returned = send_data_column_count,
            "Received DataColumnsByRoot Request"
        );

        Ok(())
    }

    /// Handle a `LightClientBootstrap` request from the peer.
    pub fn handle_light_client_bootstrap(
        self: &Arc<Self>,
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: LightClientBootstrapRequest,
    ) {
        self.terminate_response_single_item(
            peer_id,
            request_id,
            match self.chain.get_light_client_bootstrap(&request.root) {
                Ok(Some((bootstrap, _))) => Ok(Arc::new(bootstrap)),
                Ok(None) => Err((
                    RPCResponseErrorCode::ResourceUnavailable,
                    "Bootstrap not available".to_string(),
                )),
                Err(e) => {
                    error!(
                        block_root = ?request.root,
                        ?peer_id,
                        error = ?e,
                        "Error getting LightClientBootstrap instance"
                    );
                    Err((
                        RPCResponseErrorCode::ResourceUnavailable,
                        format!("{:?}", e),
                    ))
                }
            },
            Response::LightClientBootstrap,
        );
    }

    /// Handle a `LightClientOptimisticUpdate` request from the peer.
    pub fn handle_light_client_optimistic_update(
        self: &Arc<Self>,
        peer_id: PeerId,
        request_id: PeerRequestId,
    ) {
        self.terminate_response_single_item(
            peer_id,
            request_id,
            match self
                .chain
                .light_client_server_cache
                .get_latest_optimistic_update()
            {
                Some(update) => Ok(Arc::new(update)),
                None => Err((
                    RPCResponseErrorCode::ResourceUnavailable,
                    "Latest optimistic update not available".to_string(),
                )),
            },
            Response::LightClientOptimisticUpdate,
        );
    }

    /// Handle a `LightClientFinalityUpdate` request from the peer.
    pub fn handle_light_client_finality_update(
        self: &Arc<Self>,
        peer_id: PeerId,
        request_id: PeerRequestId,
    ) {
        self.terminate_response_single_item(
            peer_id,
            request_id,
            match self
                .chain
                .light_client_server_cache
                .get_latest_finality_update()
            {
                Some(update) => Ok(Arc::new(update)),
                None => Err((
                    RPCResponseErrorCode::ResourceUnavailable,
                    "Latest finality update not available".to_string(),
                )),
            },
            Response::LightClientFinalityUpdate,
        );
    }

    /// Handle a `BlocksByRange` request from the peer.
    pub async fn handle_blocks_by_range_request(
        self: Arc<Self>,
        peer_id: PeerId,
        request_id: PeerRequestId,
        req: BlocksByRangeRequest,
    ) {
        self.terminate_response_stream(
            peer_id,
            request_id,
            self.clone()
                .handle_blocks_by_range_request_inner(peer_id, request_id, req)
                .await,
            Response::BlocksByRange,
        );
    }

    /// Handle a `BlocksByRange` request from the peer.
    pub async fn handle_blocks_by_range_request_inner(
        self: Arc<Self>,
        peer_id: PeerId,
        request_id: PeerRequestId,
        req: BlocksByRangeRequest,
    ) -> Result<(), (RPCResponseErrorCode, &'static str)> {
        debug!(
            ?peer_id,
            count = req.count(),
            start_slot = ?req.start_slot(),
            "Received BlocksByRange Request"
        );

        // Should not send more than max request blocks
        let max_request_size =
            self.chain
                .epoch()
                .map_or(self.chain.spec.max_request_blocks, |epoch| {
                    match self.chain.spec.fork_name_at_epoch(epoch) {
                        ForkName::Deneb | ForkName::Electra => {
                            self.chain.spec.max_request_blocks_deneb
                        }
                        ForkName::Base
                        | ForkName::Altair
                        | ForkName::Bellatrix
                        | ForkName::Capella => self.chain.spec.max_request_blocks,
                    }
                });
        if *req.count() > max_request_size {
            return Err((
                RPCResponseErrorCode::InvalidRequest,
                "Request exceeded max size",
            ));
        }

        let forwards_block_root_iter = match self
            .chain
            .forwards_iter_block_roots(Slot::from(*req.start_slot()))
        {
            Ok(iter) => iter,
            Err(BeaconChainError::HistoricalBlockError(
                HistoricalBlockError::BlockOutOfRange {
                    slot,
                    oldest_block_slot,
                },
            )) => {
                debug!(
                    requested_slot = ?slot,
                    oldest_known_slot = ?oldest_block_slot,
                    "Range request failed during backfill"
                );
                return Err((RPCResponseErrorCode::ResourceUnavailable, "Backfilling"));
            }
            Err(e) => {
                error!(
                    request = ?req,
                    ?peer_id,
                    error = ?e,
                    "Unable to obtain root iter"
                );
                return Err((RPCResponseErrorCode::ServerError, "Database error"));
            }
        };

        // Pick out the required blocks, ignoring skip-slots.
        let mut last_block_root = None;
        let maybe_block_roots = process_results(forwards_block_root_iter, |iter| {
            iter.take_while(|(_, slot)| {
                slot.as_u64() < req.start_slot().saturating_add(*req.count())
            })
            // map skip slots to None
            .map(|(root, _)| {
                let result = if Some(root) == last_block_root {
                    None
                } else {
                    Some(root)
                };
                last_block_root = Some(root);
                result
            })
            .collect::<Vec<Option<Hash256>>>()
        });

        let block_roots = match maybe_block_roots {
            Ok(block_roots) => block_roots,
            Err(e) => {
                error!(
                    request = ?req,
                    ?peer_id,
                    error = ?e,
                    "Error during iteration over blocks"
                );
                return Err((RPCResponseErrorCode::ServerError, "Iteration error"));
            }
        };

        // remove all skip slots
        let block_roots = block_roots.into_iter().flatten().collect::<Vec<_>>();

        let current_slot = self
            .chain
            .slot()
            .unwrap_or_else(|_| self.chain.slot_clock.genesis_slot());

        let log_results = |req: BlocksByRangeRequest, peer_id, blocks_sent| {
            if blocks_sent < (*req.count() as usize) {
                debug!(
                    ?peer_id,
                    msg = "Failed to return all requested blocks",
                    start_slot = ?req.start_slot(),
                    ?current_slot,
                    requested = req.count(),
                    returned = blocks_sent,
                    "BlocksByRange outgoing response processed"
                );
            } else {
                debug!(
                    ?peer_id,
                    start_slot = ?req.start_slot(),
                    ?current_slot,
                    requested = req.count(),
                    returned = blocks_sent,
                    "BlocksByRange outgoing response processed"
                );
            }
        };

        let mut block_stream = match self.chain.get_blocks(block_roots) {
            Ok(block_stream) => block_stream,
            Err(e) => {
                error!(error = ?e, "Error getting block stream");
                return Err((RPCResponseErrorCode::ServerError, "Iterator error"));
            }
        };

        // Fetching blocks is async because it may have to hit the execution layer for payloads.
        let mut blocks_sent = 0;
        while let Some((root, result)) = block_stream.next().await {
            match result.as_ref() {
                Ok(Some(block)) => {
                    // Due to skip slots, blocks could be out of the range, we ensure they
                    // are in the range before sending
                    if block.slot() >= *req.start_slot()
                        && block.slot() < req.start_slot() + req.count()
                    {
                        blocks_sent += 1;
                        self.send_network_message(NetworkMessage::SendResponse {
                            peer_id,
                            response: Response::BlocksByRange(Some(block.clone())),
                            id: request_id,
                        });
                    }
                }
                Ok(None) => {
                    error!(
                        request = ?req,
                        ?peer_id,
                        request_root = ?root,
                        "Block in the chain is not in the store"
                    );
                    log_results(req, peer_id, blocks_sent);
                    return Err((RPCResponseErrorCode::ServerError, "Database inconsistency"));
                }
                Err(BeaconChainError::BlockHashMissingFromExecutionLayer(_)) => {
                    debug!(
                        block_root = ?root,
                        reason = "execution layer not synced",
                        "Failed to fetch execution payload for blocks by range request"
                    );
                    log_results(req, peer_id, blocks_sent);
                    // send the stream terminator
                    return Err((
                        RPCResponseErrorCode::ResourceUnavailable,
                        "Execution layer not synced",
                    ));
                }
                Err(e) => {
                    if matches!(
                        e,
                        BeaconChainError::ExecutionLayerErrorPayloadReconstruction(_block_hash, ref boxed_error)
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
                    log_results(req, peer_id, blocks_sent);
                    // send the stream terminator
                    return Err((RPCResponseErrorCode::ServerError, "Failed fetching blocks"));
                }
            }
        }

        log_results(req, peer_id, blocks_sent);
        Ok(())
    }

    /// Handle a `BlobsByRange` request from the peer.
    pub fn handle_blobs_by_range_request(
        self: Arc<Self>,
        peer_id: PeerId,
        request_id: PeerRequestId,
        req: BlobsByRangeRequest,
    ) {
        self.terminate_response_stream(
            peer_id,
            request_id,
            self.handle_blobs_by_range_request_inner(peer_id, request_id, req),
            Response::BlobsByRange,
        );
    }

    /// Handle a `BlobsByRange` request from the peer.
    fn handle_blobs_by_range_request_inner(
        &self,
        peer_id: PeerId,
        request_id: PeerRequestId,
        req: BlobsByRangeRequest,
    ) -> Result<(), (RPCResponseErrorCode, &'static str)> {
        debug!(
            ?peer_id,
            count = req.count,
            start_slot = req.start_slot,
            "Received BlobsByRange Request"
        );

        // Should not send more than max request blocks
        if req.max_blobs_requested::<T::EthSpec>() > self.chain.spec.max_request_blob_sidecars {
            return Err((
                RPCResponseErrorCode::InvalidRequest,
                "Request exceeded `MAX_REQUEST_BLOBS_SIDECARS`",
            ));
        }

        let request_start_slot = Slot::from(req.start_slot);

        let data_availability_boundary_slot = match self.chain.data_availability_boundary() {
            Some(boundary) => boundary.start_slot(T::EthSpec::slots_per_epoch()),
            None => {
                debug!("Deneb fork is disabled");
                return Err((
                    RPCResponseErrorCode::InvalidRequest,
                    "Deneb fork is disabled",
                ));
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
                ?request_start_slot,
                ?oldest_blob_slot,
                ?data_availability_boundary_slot,
                "Range request start slot is older than data availability boundary."
            );

            return if data_availability_boundary_slot < oldest_blob_slot {
                Err((
                    RPCResponseErrorCode::ResourceUnavailable,
                    "blobs pruned within boundary",
                ))
            } else {
                Err((
                    RPCResponseErrorCode::InvalidRequest,
                    "Req outside availability period",
                ))
            };
        }

        let forwards_block_root_iter =
            match self.chain.forwards_iter_block_roots(request_start_slot) {
                Ok(iter) => iter,
                Err(BeaconChainError::HistoricalBlockError(
                    HistoricalBlockError::BlockOutOfRange {
                        slot,
                        oldest_block_slot,
                    },
                )) => {
                    debug!(
                        requested_slot = ?slot,
                        oldest_known_slot = ?oldest_block_slot,
                        "Range request failed during backfill"
                    );
                    return Err((RPCResponseErrorCode::ResourceUnavailable, "Backfilling"));
                }
                Err(e) => {
                    error!(
                        request = ?req,
                        ?peer_id,
                        error = ?e,
                        "Unable to obtain root iter"
                    );
                    return Err((RPCResponseErrorCode::ServerError, "Database error"));
                }
            };

        // Use `WhenSlotSkipped::Prev` to get the most recent block root prior to
        // `request_start_slot` in order to check whether the `request_start_slot` is a skip.
        let mut last_block_root = req.start_slot.checked_sub(1).and_then(|prev_slot| {
            self.chain
                .block_root_at_slot(Slot::new(prev_slot), WhenSlotSkipped::Prev)
                .ok()
                .flatten()
        });

        // Pick out the required blocks, ignoring skip-slots.
        let maybe_block_roots = process_results(forwards_block_root_iter, |iter| {
            iter.take_while(|(_, slot)| slot.as_u64() < req.start_slot.saturating_add(req.count))
                // map skip slots to None
                .map(|(root, _)| {
                    let result = if Some(root) == last_block_root {
                        None
                    } else {
                        Some(root)
                    };
                    last_block_root = Some(root);
                    result
                })
                .collect::<Vec<Option<Hash256>>>()
        });

        let block_roots = match maybe_block_roots {
            Ok(block_roots) => block_roots,
            Err(e) => {
                error!(
                    request = ?req,
                    ?peer_id,
                    error = ?e,
                    "Error during iteration over blocks"
                );
                return Err((RPCResponseErrorCode::ServerError, "Database error"));
            }
        };

        let current_slot = self
            .chain
            .slot()
            .unwrap_or_else(|_| self.chain.slot_clock.genesis_slot());

        let log_results = |peer_id, req: BlobsByRangeRequest, blobs_sent| {
            debug!(
                ?peer_id,
                start_slot = req.start_slot,
                ?current_slot,
                requested = req.count,
                returned = blobs_sent,
                "BlobsByRange outgoing response processed"
            );
        };

        // remove all skip slots
        let block_roots = block_roots.into_iter().flatten();
        let mut blobs_sent = 0;

        for root in block_roots {
            match self.chain.get_blobs(&root) {
                Ok(blob_sidecar_list) => {
                    for blob_sidecar in blob_sidecar_list.iter() {
                        blobs_sent += 1;
                        self.send_network_message(NetworkMessage::SendResponse {
                            peer_id,
                            response: Response::BlobsByRange(Some(blob_sidecar.clone())),
                            id: request_id,
                        });
                    }
                }
                Err(e) => {
                    error!(
                        request = ?req,
                        ?peer_id,
                        block_root = ?root,
                        error = ?e,
                        "Error fetching blobs block root"
                    );
                    log_results(peer_id, req, blobs_sent);

                    return Err((
                        RPCResponseErrorCode::ServerError,
                        "No blobs and failed fetching corresponding block",
                    ));
                }
            }
        }
        log_results(peer_id, req, blobs_sent);

        Ok(())
    }

    /// Handle a `DataColumnsByRange` request from the peer.
    pub fn handle_data_columns_by_range_request(
        &self,
        peer_id: PeerId,
        request_id: PeerRequestId,
        req: DataColumnsByRangeRequest,
    ) {
        self.terminate_response_stream(
            peer_id,
            request_id,
            self.handle_data_columns_by_range_request_inner(peer_id, request_id, req),
            Response::DataColumnsByRange,
        );
    }

    /// Handle a `DataColumnsByRange` request from the peer.
    pub fn handle_data_columns_by_range_request_inner(
        &self,
        peer_id: PeerId,
        request_id: PeerRequestId,
        req: DataColumnsByRangeRequest,
    ) -> Result<(), (RPCResponseErrorCode, &'static str)> {
        debug!(
            ?peer_id,
            count = req.count,
            start_slot = req.start_slot,
            "Received DataColumnsByRange Request"
        );

        // Should not send more than max request data columns
        if req.max_requested::<T::EthSpec>() > self.chain.spec.max_request_data_column_sidecars {
            return Err((
                RPCResponseErrorCode::InvalidRequest,
                "Request exceeded `MAX_REQUEST_BLOBS_SIDECARS`",
            ));
        }

        let request_start_slot = Slot::from(req.start_slot);

        let data_availability_boundary_slot = match self.chain.data_availability_boundary() {
            Some(boundary) => boundary.start_slot(T::EthSpec::slots_per_epoch()),
            None => {
                debug!("Deneb fork is disabled");
                return Err((
                    RPCResponseErrorCode::InvalidRequest,
                    "Deneb fork is disabled",
                ));
            }
        };

        let oldest_data_column_slot = self
            .chain
            .store
            .get_data_column_info()
            .oldest_data_column_slot
            .unwrap_or(data_availability_boundary_slot);

        if request_start_slot < oldest_data_column_slot {
            debug!(
                ?request_start_slot,
                ?oldest_data_column_slot,
                ?data_availability_boundary_slot,
                "Range request start slot is older than data availability boundary."
            );

            return if data_availability_boundary_slot < oldest_data_column_slot {
                Err((
                    RPCResponseErrorCode::ResourceUnavailable,
                    "blobs pruned within boundary",
                ))
            } else {
                Err((
                    RPCResponseErrorCode::InvalidRequest,
                    "Req outside availability period",
                ))
            };
        }

        let forwards_block_root_iter =
            match self.chain.forwards_iter_block_roots(request_start_slot) {
                Ok(iter) => iter,
                Err(BeaconChainError::HistoricalBlockError(
                    HistoricalBlockError::BlockOutOfRange {
                        slot,
                        oldest_block_slot,
                    },
                )) => {
                    debug!(
                        requested_slot = ?slot,
                        oldest_known_slot = ?oldest_block_slot,
                        "Range request failed during backfill"
                    );
                    return Err((RPCResponseErrorCode::ResourceUnavailable, "Backfilling"));
                }
                Err(e) => {
                    error!(
                        request = ?req,
                        ?peer_id,
                        error = ?e,
                        "Unable to obtain root iter"
                    );
                    return Err((RPCResponseErrorCode::ServerError, "Database error"));
                }
            };

        // Use `WhenSlotSkipped::Prev` to get the most recent block root prior to
        // `request_start_slot` in order to check whether the `request_start_slot` is a skip.
        let mut last_block_root = req.start_slot.checked_sub(1).and_then(|prev_slot| {
            self.chain
                .block_root_at_slot(Slot::new(prev_slot), WhenSlotSkipped::Prev)
                .ok()
                .flatten()
        });

        // Pick out the required blocks, ignoring skip-slots.
        let maybe_block_roots = process_results(forwards_block_root_iter, |iter| {
            iter.take_while(|(_, slot)| slot.as_u64() < req.start_slot.saturating_add(req.count))
                // map skip slots to None
                .map(|(root, _)| {
                    let result = if Some(root) == last_block_root {
                        None
                    } else {
                        Some(root)
                    };
                    last_block_root = Some(root);
                    result
                })
                .collect::<Vec<Option<Hash256>>>()
        });

        let block_roots = match maybe_block_roots {
            Ok(block_roots) => block_roots,
            Err(e) => {
                error!(
                    request = ?req,
                    ?peer_id,
                    error = ?e,
                    "Error during iteration over blocks"
                );
                return Err((RPCResponseErrorCode::ServerError, "Database error"));
            }
        };

        // remove all skip slots
        let block_roots = block_roots.into_iter().flatten();
        let mut data_columns_sent = 0;

        for root in block_roots {
            for index in &req.columns {
                match self.chain.get_data_column(&root, index) {
                    Ok(Some(data_column_sidecar)) => {
                        data_columns_sent += 1;
                        self.send_network_message(NetworkMessage::SendResponse {
                            peer_id,
                            response: Response::DataColumnsByRange(Some(
                                data_column_sidecar.clone(),
                            )),
                            id: request_id,
                        });
                    }
                    Ok(None) => {} // no-op
                    Err(e) => {
                        error!(
                            request = ?req,
                            ?peer_id,
                            block_root = ?root,
                            error = ?e,
                            "Error fetching data columns block root"
                        );
                        return Err((
                            RPCResponseErrorCode::ServerError,
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
            ?peer_id,
            start_slot = req.start_slot,
            ?current_slot,
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
        request_id: PeerRequestId,
        result: Result<R, (RPCResponseErrorCode, String)>,
        into_response: F,
    ) {
        match result {
            Ok(resp) => {
                // Not necessary to explicitly send a termination message if this InboundRequest
                // returns <= 1 for InboundRequest::expected_responses
                // https://github.com/sigp/lighthouse/blob/3058b96f2560f1da04ada4f9d8ba8e5651794ff6/beacon_node/lighthouse_network/src/rpc/handler.rs#L555-L558
                self.send_network_message(NetworkMessage::SendResponse {
                    peer_id,
                    response: into_response(resp),
                    id: request_id,
                });
            }
            Err((error_code, reason)) => {
                self.send_error_response(peer_id, error_code, reason, request_id);
            }
        }
    }

    /// Helper function to ensure streamed protocols with multiple responses always end with either
    /// a stream termination or an error
    fn terminate_response_stream<R, F: FnOnce(Option<R>) -> Response<T::EthSpec>>(
        &self,
        peer_id: PeerId,
        request_id: PeerRequestId,
        result: Result<(), (RPCResponseErrorCode, &'static str)>,
        into_response: F,
    ) {
        match result {
            Ok(_) => self.send_network_message(NetworkMessage::SendResponse {
                peer_id,
                response: into_response(None),
                id: request_id,
            }),
            Err((error_code, reason)) => {
                self.send_error_response(peer_id, error_code, reason.into(), request_id);
            }
        }
    }
}
