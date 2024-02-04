use crate::network_beacon_processor::{NetworkBeaconProcessor, FUTURE_SLOT_TOLERANCE};
use crate::service::NetworkMessage;
use crate::status::ToStatusMessage;
use crate::sync::SyncMessage;
use beacon_chain::{BeaconChainError, BeaconChainTypes, HistoricalBlockError, WhenSlotSkipped};
use beacon_processor::SendOnDrop;
use itertools::process_results;
use lighthouse_network::rpc::methods::{BlobsByRangeRequest, BlobsByRootRequest};
use lighthouse_network::rpc::StatusMessage;
use lighthouse_network::rpc::*;
use lighthouse_network::{PeerId, PeerRequestId, ReportSource, Response, SyncInfo};
use slog::{debug, error, warn};
use slot_clock::SlotClock;
use std::collections::{hash_map::Entry, HashMap};
use std::sync::Arc;
use task_executor::TaskExecutor;
use tokio_stream::StreamExt;
use types::blob_sidecar::BlobIdentifier;
use types::{Epoch, EthSpec, ForkName, Hash256, Slot};

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
                debug!(self.log, "Handshake Failure"; "peer" => %peer_id, "reason" => irrelevant_reason);
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
            Err(e) => error!(self.log, "Could not process status message";
                "peer" => %peer_id,
                "error" => ?e
            ),
        }
    }

    /// Handle a `BlocksByRoot` request from the peer.
    pub fn handle_blocks_by_root_request(
        self: Arc<Self>,
        executor: TaskExecutor,
        send_on_drop: SendOnDrop,
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: BlocksByRootRequest,
    ) {
        let requested_blocks = request.block_roots().len();
        let mut block_stream = match self
            .chain
            .get_blocks_checking_early_attester_cache(request.block_roots().to_vec(), &executor)
        {
            Ok(block_stream) => block_stream,
            Err(e) => return error!(self.log, "Error getting block stream"; "error" => ?e),
        };
        // Fetching blocks is async because it may have to hit the execution layer for payloads.
        executor.spawn(
            async move {
                let mut send_block_count = 0;
                let mut send_response = true;
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
                                self.log,
                                "Peer requested unknown block";
                                "peer" => %peer_id,
                                "request_root" => ?root
                            );
                        }
                        Err(BeaconChainError::BlockHashMissingFromExecutionLayer(_)) => {
                            debug!(
                                self.log,
                                "Failed to fetch execution payload for blocks by root request";
                                "block_root" => ?root,
                                "reason" => "execution layer not synced",
                            );
                            // send the stream terminator
                            self.send_error_response(
                                peer_id,
                                RPCResponseErrorCode::ResourceUnavailable,
                                "Execution layer not synced".into(),
                                request_id,
                            );
                            send_response = false;
                            break;
                        }
                        Err(e) => {
                            debug!(
                                self.log,
                                "Error fetching block for peer";
                                "peer" => %peer_id,
                                "request_root" => ?root,
                                "error" => ?e,
                            );
                        }
                    }
                }
                debug!(
                    self.log,
                    "Received BlocksByRoot Request";
                    "peer" => %peer_id,
                    "requested" => requested_blocks,
                    "returned" => %send_block_count
                );

                // send stream termination
                if send_response {
                    self.send_response(peer_id, Response::BlocksByRoot(None), request_id);
                }
                drop(send_on_drop);
            },
            "load_blocks_by_root_blocks",
        )
    }
    /// Handle a `BlobsByRoot` request from the peer.
    pub fn handle_blobs_by_root_request(
        self: Arc<Self>,
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: BlobsByRootRequest,
    ) {
        let Some(requested_root) = request.blob_ids.as_slice().first().map(|id| id.block_root)
        else {
            // No blob ids requested.
            return;
        };
        let requested_indices = request
            .blob_ids
            .as_slice()
            .iter()
            .map(|id| id.index)
            .collect::<Vec<_>>();
        let mut send_blob_count = 0;
        let send_response = true;

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
                            self.log,
                            "Error fetching blob for peer";
                            "peer" => %peer_id,
                            "request_root" => ?root,
                            "error" => ?e,
                        );
                    }
                }
            }
        }
        debug!(
            self.log,
            "Received BlobsByRoot Request";
            "peer" => %peer_id,
            "request_root" => %requested_root,
            "request_indices" => ?requested_indices,
            "returned" => send_blob_count
        );

        // send stream termination
        if send_response {
            self.send_response(peer_id, Response::BlobsByRoot(None), request_id);
        }
    }

    /// Handle a `BlocksByRoot` request from the peer.
    pub fn handle_light_client_bootstrap(
        self: &Arc<Self>,
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: LightClientBootstrapRequest,
    ) {
        let block_root = request.root;
        match self.chain.get_light_client_bootstrap(&block_root) {
            Ok(Some((bootstrap, _))) => self.send_response(
                peer_id,
                Response::LightClientBootstrap(bootstrap),
                request_id,
            ),
            Ok(None) => self.send_error_response(
                peer_id,
                RPCResponseErrorCode::ResourceUnavailable,
                "Bootstrap not available".into(),
                request_id,
            ),
            Err(e) => {
                self.send_error_response(
                    peer_id,
                    RPCResponseErrorCode::ResourceUnavailable,
                    "Bootstrap not available".into(),
                    request_id,
                );
                error!(self.log, "Error getting LightClientBootstrap instance";
                    "block_root" => ?block_root,
                    "peer" => %peer_id,
                    "error" => ?e
                )
            }
        };
    }

    /// Handle a `BlocksByRange` request from the peer.
    pub fn handle_blocks_by_range_request(
        self: Arc<Self>,
        executor: TaskExecutor,
        send_on_drop: SendOnDrop,
        peer_id: PeerId,
        request_id: PeerRequestId,
        req: BlocksByRangeRequest,
    ) {
        debug!(self.log, "Received BlocksByRange Request";
            "peer_id" => %peer_id,
            "count" => req.count(),
            "start_slot" => req.start_slot(),
        );

        // Should not send more than max request blocks
        let max_request_size =
            self.chain
                .epoch()
                .map_or(self.chain.spec.max_request_blocks, |epoch| {
                    match self.chain.spec.fork_name_at_epoch(epoch) {
                        ForkName::Deneb => self.chain.spec.max_request_blocks_deneb,
                        ForkName::Base | ForkName::Altair | ForkName::Merge | ForkName::Capella => {
                            self.chain.spec.max_request_blocks
                        }
                    }
                });
        if *req.count() > max_request_size {
            return self.send_error_response(
                peer_id,
                RPCResponseErrorCode::InvalidRequest,
                format!("Request exceeded max size {max_request_size}"),
                request_id,
            );
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
                debug!(self.log, "Range request failed during backfill";
                    "requested_slot" => slot,
                    "oldest_known_slot" => oldest_block_slot
                );
                return self.send_error_response(
                    peer_id,
                    RPCResponseErrorCode::ResourceUnavailable,
                    "Backfilling".into(),
                    request_id,
                );
            }
            Err(e) => {
                self.send_error_response(
                    peer_id,
                    RPCResponseErrorCode::ServerError,
                    "Database error".into(),
                    request_id,
                );
                return error!(self.log, "Unable to obtain root iter";
                    "request" => ?req,
                    "peer" => %peer_id,
                    "error" => ?e
                );
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
                return error!(self.log, "Error during iteration over blocks";
                    "request" => ?req,
                    "peer" => %peer_id,
                    "error" => ?e
                )
            }
        };

        // remove all skip slots
        let block_roots = block_roots.into_iter().flatten().collect::<Vec<_>>();

        let mut block_stream = match self.chain.get_blocks(block_roots, &executor) {
            Ok(block_stream) => block_stream,
            Err(e) => return error!(self.log, "Error getting block stream"; "error" => ?e),
        };

        // Fetching blocks is async because it may have to hit the execution layer for payloads.
        executor.spawn(
            async move {
                let mut blocks_sent = 0;
                let mut send_response = true;

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
                                self.log,
                                "Block in the chain is not in the store";
                                "request" => ?req,
                                "peer" => %peer_id,
                                "request_root" => ?root
                            );
                            self.send_error_response(
                                peer_id,
                                RPCResponseErrorCode::ServerError,
                                "Database inconsistency".into(),
                                request_id,
                            );
                            send_response = false;
                            break;
                        }
                        Err(BeaconChainError::BlockHashMissingFromExecutionLayer(_)) => {
                            debug!(
                                self.log,
                                "Failed to fetch execution payload for blocks by range request";
                                "block_root" => ?root,
                                "reason" => "execution layer not synced",
                            );
                            // send the stream terminator
                            self.send_error_response(
                                peer_id,
                                RPCResponseErrorCode::ResourceUnavailable,
                                "Execution layer not synced".into(),
                                request_id,
                            );
                            send_response = false;
                            break;
                        }
                        Err(e) => {
                            if matches!(
                                e,
                                BeaconChainError::ExecutionLayerErrorPayloadReconstruction(_block_hash, ref boxed_error)
                                if matches!(**boxed_error, execution_layer::Error::EngineError(_))
                            ) {
                                warn!(
                                    self.log,
                                    "Error rebuilding payload for peer";
                                    "info" => "this may occur occasionally when the EE is busy",
                                    "block_root" => ?root,
                                    "error" => ?e,
                                );
                            } else {
                                error!(
                                    self.log,
                                    "Error fetching block for peer";
                                    "block_root" => ?root,
                                    "error" => ?e
                                );
                            }

                            // send the stream terminator
                            self.send_error_response(
                                peer_id,
                                RPCResponseErrorCode::ServerError,
                                "Failed fetching blocks".into(),
                                request_id,
                            );
                            send_response = false;
                            break;
                        }
                    }
                }

                let current_slot = self
                    .chain
                    .slot()
                    .unwrap_or_else(|_| self.chain.slot_clock.genesis_slot());

                if blocks_sent < (*req.count() as usize) {
                    debug!(
                        self.log,
                        "BlocksByRange outgoing response processed";
                        "peer" => %peer_id,
                        "msg" => "Failed to return all requested blocks",
                        "start_slot" => req.start_slot(),
                        "current_slot" => current_slot,
                        "requested" => req.count(),
                        "returned" => blocks_sent
                    );
                } else {
                    debug!(
                        self.log,
                        "BlocksByRange outgoing response processed";
                        "peer" => %peer_id,
                        "start_slot" => req.start_slot(),
                        "current_slot" => current_slot,
                        "requested" => req.count(),
                        "returned" => blocks_sent
                    );
                }

                if send_response {
                    // send the stream terminator
                    self.send_network_message(NetworkMessage::SendResponse {
                        peer_id,
                        response: Response::BlocksByRange(None),
                        id: request_id,
                    });
                }

                drop(send_on_drop);
            },
            "load_blocks_by_range_blocks",
        );
    }

    /// Handle a `BlobsByRange` request from the peer.
    pub fn handle_blobs_by_range_request(
        self: Arc<Self>,
        peer_id: PeerId,
        request_id: PeerRequestId,
        req: BlobsByRangeRequest,
    ) {
        debug!(self.log, "Received BlobsByRange Request";
            "peer_id" => %peer_id,
            "count" => req.count,
            "start_slot" => req.start_slot,
        );

        // Should not send more than max request blocks
        if req.max_blobs_requested::<T::EthSpec>() > self.chain.spec.max_request_blob_sidecars {
            return self.send_error_response(
                peer_id,
                RPCResponseErrorCode::InvalidRequest,
                "Request exceeded `MAX_REQUEST_BLOBS_SIDECARS`".into(),
                request_id,
            );
        }

        let request_start_slot = Slot::from(req.start_slot);

        let data_availability_boundary_slot = match self.chain.data_availability_boundary() {
            Some(boundary) => boundary.start_slot(T::EthSpec::slots_per_epoch()),
            None => {
                debug!(self.log, "Deneb fork is disabled");
                self.send_error_response(
                    peer_id,
                    RPCResponseErrorCode::InvalidRequest,
                    "Deneb fork is disabled".into(),
                    request_id,
                );
                return;
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
                self.log,
                "Range request start slot is older than data availability boundary.";
                "requested_slot" => request_start_slot,
                "oldest_blob_slot" => oldest_blob_slot,
                "data_availability_boundary" => data_availability_boundary_slot
            );

            return if data_availability_boundary_slot < oldest_blob_slot {
                self.send_error_response(
                    peer_id,
                    RPCResponseErrorCode::ResourceUnavailable,
                    "blobs pruned within boundary".into(),
                    request_id,
                )
            } else {
                self.send_error_response(
                    peer_id,
                    RPCResponseErrorCode::InvalidRequest,
                    "Req outside availability period".into(),
                    request_id,
                )
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
                    debug!(self.log, "Range request failed during backfill";
                        "requested_slot" => slot,
                        "oldest_known_slot" => oldest_block_slot
                    );
                    return self.send_error_response(
                        peer_id,
                        RPCResponseErrorCode::ResourceUnavailable,
                        "Backfilling".into(),
                        request_id,
                    );
                }
                Err(e) => {
                    self.send_error_response(
                        peer_id,
                        RPCResponseErrorCode::ServerError,
                        "Database error".into(),
                        request_id,
                    );
                    return error!(self.log, "Unable to obtain root iter";
                        "request" => ?req,
                        "peer" => %peer_id,
                        "error" => ?e
                    );
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
                return error!(self.log, "Error during iteration over blocks";
                    "request" => ?req,
                    "peer" => %peer_id,
                    "error" => ?e
                )
            }
        };

        // remove all skip slots
        let block_roots = block_roots.into_iter().flatten();

        let mut blobs_sent = 0;
        let mut send_response = true;

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
                        self.log,
                        "Error fetching blobs block root";
                        "request" => ?req,
                        "peer" => %peer_id,
                        "block_root" => ?root,
                        "error" => ?e
                    );
                    self.send_error_response(
                        peer_id,
                        RPCResponseErrorCode::ServerError,
                        "No blobs and failed fetching corresponding block".into(),
                        request_id,
                    );
                    send_response = false;
                    break;
                }
            }
        }

        let current_slot = self
            .chain
            .slot()
            .unwrap_or_else(|_| self.chain.slot_clock.genesis_slot());

        debug!(
            self.log,
            "BlobsByRange Response processed";
            "peer" => %peer_id,
            "start_slot" => req.start_slot,
            "current_slot" => current_slot,
            "requested" => req.count,
            "returned" => blobs_sent
        );

        if send_response {
            // send the stream terminator
            self.send_network_message(NetworkMessage::SendResponse {
                peer_id,
                response: Response::BlobsByRange(None),
                id: request_id,
            });
        }
    }
}
