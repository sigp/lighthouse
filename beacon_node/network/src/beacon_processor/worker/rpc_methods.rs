use std::sync::Arc;

use crate::beacon_processor::{worker::FUTURE_SLOT_TOLERANCE, SendOnDrop};
use crate::service::NetworkMessage;
use crate::status::ToStatusMessage;
use crate::sync::SyncMessage;
use beacon_chain::{BeaconChainError, BeaconChainTypes, HistoricalBlockError, WhenSlotSkipped};
use itertools::process_results;
use lighthouse_network::rpc::methods::{
    BlobsByRangeRequest, BlobsByRootRequest, MAX_REQUEST_BLOBS_SIDECARS,
};
use lighthouse_network::rpc::StatusMessage;
use lighthouse_network::rpc::*;
use lighthouse_network::{PeerId, PeerRequestId, ReportSource, Response, SyncInfo};
use slog::{debug, error, warn};
use slot_clock::SlotClock;
use task_executor::TaskExecutor;
use tokio_stream::StreamExt;
use types::{light_client_bootstrap::LightClientBootstrap, Epoch, EthSpec, Hash256, Slot};

use super::Worker;

impl<T: BeaconChainTypes> Worker<T> {
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
        self,
        executor: TaskExecutor,
        send_on_drop: SendOnDrop,
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: BlocksByRootRequest,
    ) {
        let requested_blocks = request.block_roots.len();
        let mut block_stream = match self
            .chain
            .get_blocks_checking_early_attester_cache(request.block_roots.into(), &executor)
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
        self,
        executor: TaskExecutor,
        send_on_drop: SendOnDrop,
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: BlobsByRootRequest,
    ) {
        // Fetching blocks is async because it may have to hit the execution layer for payloads.
        executor.spawn(
            async move {
                let mut send_block_count = 0;
                let mut send_response = true;
                for root in request.block_roots.iter() {
                    match self
                        .chain
                        .get_block_and_blobs_checking_early_attester_cache(root)
                        .await
                    {
                        Ok(Some(block_and_blobs)) => {
                            self.send_response(
                                peer_id,
                                Response::BlobsByRoot(Some(block_and_blobs)),
                                request_id,
                            );
                            send_block_count += 1;
                        }
                        Ok(None) => {
                            debug!(
                                self.log,
                                "Peer requested unknown block and blobs";
                                "peer" => %peer_id,
                                "request_root" => ?root
                            );
                        }
                        Err(BeaconChainError::BlobsUnavailable) => {
                            error!(
                                self.log,
                                "No blobs in the store for block root";
                                "request" => ?request,
                                "peer" => %peer_id,
                                "block_root" => ?root
                            );
                            self.send_error_response(
                                peer_id,
                                RPCResponseErrorCode::BlobsNotFoundForBlock,
                                "Blobs not found for block root".into(),
                                request_id,
                            );
                            send_response = false;
                            break;
                        }
                        Err(BeaconChainError::NoKzgCommitmentsFieldOnBlock) => {
                            debug!(
                                self.log,
                                "Peer requested blobs for a pre-eip4844 block";
                                "peer" => %peer_id,
                                "block_root" => ?root,
                            );
                            self.send_error_response(
                                peer_id,
                                RPCResponseErrorCode::ResourceUnavailable,
                                "Failed reading field kzg_commitments from block".into(),
                                request_id,
                            );
                            send_response = false;
                            break;
                        }
                        Err(BeaconChainError::BlobsOlderThanDataAvailabilityBoundary(block_epoch)) => {
                            debug!(
                                    self.log,
                                    "Peer requested block and blobs older than the data availability \
                                    boundary for ByRoot request, no blob found";
                                    "peer" => %peer_id,
                                    "request_root" => ?root,
                                    "block_epoch" => ?block_epoch,
                                );
                            self.send_error_response(
                                peer_id,
                                RPCResponseErrorCode::ResourceUnavailable,
                                "Blobs older than data availability boundary".into(),
                                request_id,
                            );
                            send_response = false;
                            break;
                        }
                        Err(BeaconChainError::BlockHashMissingFromExecutionLayer(_)) => {
                            debug!(
                                self.log,
                                "Failed to fetch execution payload for block and blobs by root request";
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
                    "Received BlobsByRoot Request";
                    "peer" => %peer_id,
                    "requested" => request.block_roots.len(),
                    "returned" => send_block_count
                );

                // send stream termination
                if send_response {
                    self.send_response(peer_id, Response::BlobsByRoot(None), request_id);
                }
                drop(send_on_drop);
            },
            "load_blobs_by_root_blocks",
        )
    }

    /// Handle a `BlocksByRoot` request from the peer.
    pub fn handle_light_client_bootstrap(
        self,
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: LightClientBootstrapRequest,
    ) {
        let block_root = request.root;
        let state_root = match self.chain.get_blinded_block(&block_root) {
            Ok(signed_block) => match signed_block {
                Some(signed_block) => signed_block.state_root(),
                None => {
                    self.send_error_response(
                        peer_id,
                        RPCResponseErrorCode::ResourceUnavailable,
                        "Bootstrap not available".into(),
                        request_id,
                    );
                    return;
                }
            },
            Err(_) => {
                self.send_error_response(
                    peer_id,
                    RPCResponseErrorCode::ResourceUnavailable,
                    "Bootstrap not available".into(),
                    request_id,
                );
                return;
            }
        };
        let mut beacon_state = match self.chain.get_state(&state_root, None) {
            Ok(beacon_state) => match beacon_state {
                Some(state) => state,
                None => {
                    self.send_error_response(
                        peer_id,
                        RPCResponseErrorCode::ResourceUnavailable,
                        "Bootstrap not available".into(),
                        request_id,
                    );
                    return;
                }
            },
            Err(_) => {
                self.send_error_response(
                    peer_id,
                    RPCResponseErrorCode::ResourceUnavailable,
                    "Bootstrap not available".into(),
                    request_id,
                );
                return;
            }
        };
        let bootstrap = match LightClientBootstrap::from_beacon_state(&mut beacon_state) {
            Ok(bootstrap) => bootstrap,
            Err(_) => {
                self.send_error_response(
                    peer_id,
                    RPCResponseErrorCode::ResourceUnavailable,
                    "Bootstrap not available".into(),
                    request_id,
                );
                return;
            }
        };
        self.send_response(
            peer_id,
            Response::LightClientBootstrap(bootstrap),
            request_id,
        )
    }

    /// Handle a `BlocksByRange` request from the peer.
    pub fn handle_blocks_by_range_request(
        self,
        executor: TaskExecutor,
        send_on_drop: SendOnDrop,
        peer_id: PeerId,
        request_id: PeerRequestId,
        req: BlocksByRangeRequest,
    ) {
        debug!(self.log, "Received BlocksByRange Request";
            "peer_id" => %peer_id,
            "count" => req.count,
            "start_slot" => req.start_slot,
        );

        // Should not send more than max request blocks
        if req.count > MAX_REQUEST_BLOCKS {
            return self.send_error_response(
                peer_id,
                RPCResponseErrorCode::InvalidRequest,
                "Request exceeded `MAX_REQUEST_BLOBS_SIDECARS`".into(),
                request_id,
            );
        }

        let forwards_block_root_iter = match self
            .chain
            .forwards_iter_block_roots(Slot::from(req.start_slot))
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
        let mut last_block_root = req
            .start_slot
            .checked_sub(1)
            .map(|prev_slot| {
                self.chain
                    .block_root_at_slot(Slot::new(prev_slot), WhenSlotSkipped::Prev)
            })
            .transpose()
            .ok()
            .flatten()
            .flatten();
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
                            if block.slot() >= req.start_slot
                                && block.slot() < req.start_slot + req.count
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

                if blocks_sent < (req.count as usize) {
                    debug!(
                        self.log,
                        "BlocksByRange outgoing response processed";
                        "peer" => %peer_id,
                        "msg" => "Failed to return all requested blocks",
                        "start_slot" => req.start_slot,
                        "current_slot" => current_slot,
                        "requested" => req.count,
                        "returned" => blocks_sent
                    );
                } else {
                    debug!(
                        self.log,
                        "BlocksByRange outgoing response processed";
                        "peer" => %peer_id,
                        "start_slot" => req.start_slot,
                        "current_slot" => current_slot,
                        "requested" => req.count,
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
        self,
        _executor: TaskExecutor,
        send_on_drop: SendOnDrop,
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
        if req.count > MAX_REQUEST_BLOBS_SIDECARS {
            return self.send_error_response(
                peer_id,
                RPCResponseErrorCode::InvalidRequest,
                "Request exceeded `MAX_REQUEST_BLOBS_SIDECARS`".into(),
                request_id,
            );
        }

        let data_availability_boundary = match self.chain.data_availability_boundary() {
            Some(boundary) => boundary,
            None => {
                debug!(self.log, "Eip4844 fork is disabled");
                self.send_error_response(
                    peer_id,
                    RPCResponseErrorCode::ServerError,
                    "Eip4844 fork is disabled".into(),
                    request_id,
                );
                return;
            }
        };

        let start_slot = Slot::from(req.start_slot);
        let start_epoch = start_slot.epoch(T::EthSpec::slots_per_epoch());

        // If the peer requests data from beyond the data availability boundary we altruistically
        // cap to the right time range.
        let serve_blobs_from_slot = if start_epoch < data_availability_boundary {
            // Attempt to serve from the earliest block in our database, falling back to the data
            // availability boundary
            let oldest_blob_slot =
                self.chain.store.get_blob_info().oldest_blob_slot.unwrap_or(
                    data_availability_boundary.start_slot(T::EthSpec::slots_per_epoch()),
                );

            debug!(
                self.log,
                "Range request start slot is older than data availability boundary";
                "requested_slot" => req.start_slot,
                "oldest_known_slot" => oldest_blob_slot,
                "data_availability_boundary" => data_availability_boundary
            );

            // Check if the request is entirely out of the data availability period. The
            // `oldest_blob_slot` is the oldest slot in the database, so includes a margin of error
            // controlled by our prune margin.
            let end_request_slot = start_slot + req.count;
            if oldest_blob_slot < end_request_slot {
                return self.send_error_response(
                    peer_id,
                    RPCResponseErrorCode::InvalidRequest,
                    "Request outside of data availability period".into(),
                    request_id,
                );
            }
            std::cmp::max(oldest_blob_slot, start_slot)
        } else {
            start_slot
        };

        // If the peer requests data from beyond the data availability boundary we altruistically cap to the right time range
        let forwards_block_root_iter =
            match self.chain.forwards_iter_block_roots(serve_blobs_from_slot) {
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
        let mut last_block_root = req
            .start_slot
            .checked_sub(1)
            .map(|prev_slot| {
                self.chain
                    .block_root_at_slot(Slot::new(prev_slot), WhenSlotSkipped::Prev)
            })
            .transpose()
            .ok()
            .flatten()
            .flatten();
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
        let block_roots = block_roots.into_iter().flatten().collect::<Vec<_>>();

        let mut blobs_sent = 0;
        let mut send_response = true;

        for root in block_roots {
            match self.chain.get_blobs(&root, data_availability_boundary) {
                Ok(Some(blobs)) => {
                    blobs_sent += 1;
                    self.send_network_message(NetworkMessage::SendResponse {
                        peer_id,
                        response: Response::BlobsByRange(Some(Arc::new(blobs))),
                        id: request_id,
                    });
                }
                Ok(None) => {
                    error!(
                        self.log,
                        "No blobs or block in the store for block root";
                        "request" => ?req,
                        "peer" => %peer_id,
                        "block_root" => ?root
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
                Err(BeaconChainError::BlobsUnavailable) => {
                    error!(
                        self.log,
                        "No blobs in the store for block root";
                        "request" => ?req,
                        "peer" => %peer_id,
                        "block_root" => ?root
                    );
                    self.send_error_response(
                        peer_id,
                        RPCResponseErrorCode::ResourceUnavailable,
                        "Blobs unavailable".into(),
                        request_id,
                    );
                    send_response = false;
                    break;
                }
                Err(e) => {
                    error!(
                        self.log,
                        "Error fetching blinded block for block root";
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

        if blobs_sent < (req.count as usize) {
            debug!(
                self.log,
                "BlobsByRange Response processed";
                "peer" => %peer_id,
                "msg" => "Failed to return all requested blobs",
                "start_slot" => req.start_slot,
                "current_slot" => current_slot,
                "requested" => req.count,
                "returned" => blobs_sent
            );
        } else {
            debug!(
                self.log,
                "BlobsByRange Response processed";
                "peer" => %peer_id,
                "start_slot" => req.start_slot,
                "current_slot" => current_slot,
                "requested" => req.count,
                "returned" => blobs_sent
            );
        }

        if send_response {
            // send the stream terminator
            self.send_network_message(NetworkMessage::SendResponse {
                peer_id,
                response: Response::BlobsByRange(None),
                id: request_id,
            });
        }

        drop(send_on_drop);
    }
}
