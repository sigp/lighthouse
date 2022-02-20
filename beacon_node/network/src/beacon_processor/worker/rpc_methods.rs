use crate::beacon_processor::{worker::FUTURE_SLOT_TOLERANCE, SendOnDrop};
use crate::service::NetworkMessage;
use crate::status::ToStatusMessage;
use crate::sync::SyncMessage;
use beacon_chain::{BeaconChainError, BeaconChainTypes, HistoricalBlockError, WhenSlotSkipped};
use itertools::process_results;
use lighthouse_network::rpc::StatusMessage;
use lighthouse_network::rpc::*;
use lighthouse_network::{PeerId, PeerRequestId, ReportSource, Response, SyncInfo};
use slog::{debug, error};
use lighthouse_network::rpc::methods::TxBlobsByRangeRequest;
use slot_clock::SlotClock;
use std::sync::Arc;
use task_executor::TaskExecutor;
use types::{Epoch, EthSpec, Hash256, Slot};

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
            Err(e) => error!(self.log, "Could not process status message"; "error" => ?e),
        }
    }

    pub fn handle_tx_blobs_by_range_request(
        &self,
        peer_id: PeerId,
        request_id: PeerRequestId,
        mut req: TxBlobsByRangeRequest,
    ) {
        //FIXME(sean)
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
        // Fetching blocks is async because it may have to hit the execution layer for payloads.
        executor.spawn(
            async move {
                let mut send_block_count = 0;
                let mut send_response = true;
                for root in request.block_roots.iter() {
                    match self
                        .chain
                        .get_block_checking_early_attester_cache(root)
                        .await
                    {
                        Ok(Some(block)) => {
                            self.send_response(
                                peer_id,
                                Response::BlocksByRoot(Some(block)),
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
                    "requested" => request.block_roots.len(),
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

    /// Handle a `BlocksByRange` request from the peer.
    pub fn handle_blocks_by_range_request(
        self,
        executor: TaskExecutor,
        send_on_drop: SendOnDrop,
        peer_id: PeerId,
        request_id: PeerRequestId,
        mut req: BlocksByRangeRequest,
    ) {
        debug!(self.log, "Received BlocksByRange Request";
            "peer_id" => %peer_id,
            "count" => req.count,
            "start_slot" => req.start_slot,
        );

        // Should not send more than max request blocks
        if req.count > MAX_REQUEST_BLOCKS {
            req.count = MAX_REQUEST_BLOCKS;
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
                debug!(self.log, "Range request failed during backfill"; "requested_slot" => slot, "oldest_known_slot" => oldest_block_slot);
                return self.send_error_response(
                    peer_id,
                    RPCResponseErrorCode::ResourceUnavailable,
                    "Backfilling".into(),
                    request_id,
                );
            }
            Err(e) => return error!(self.log, "Unable to obtain root iter"; "error" => ?e),
        };

        // Pick out the required blocks, ignoring skip-slots.
        let mut last_block_root = None;
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
            Err(e) => return error!(self.log, "Error during iteration over blocks"; "error" => ?e),
        };

        // remove all skip slots
        let block_roots = block_roots.into_iter().flatten().collect::<Vec<_>>();

        // Fetching blocks is async because it may have to hit the execution layer for payloads.
        executor.spawn(
            async move {
                let mut blocks_sent = 0;
                let mut send_response = true;

                for root in block_roots {
                    match self.chain.get_block(&root).await {
                        Ok(Some(block)) => {
                            // Due to skip slots, blocks could be out of the range, we ensure they
                            // are in the range before sending
                            if block.slot() >= req.start_slot
                                && block.slot() < req.start_slot + req.count
                            {
                                blocks_sent += 1;
                                self.send_network_message(NetworkMessage::SendResponse {
                                    peer_id,
                                    response: Response::BlocksByRange(Some(Arc::new(block))),
                                    id: request_id,
                                });
                            }
                        }
                        Ok(None) => {
                            error!(
                                self.log,
                                "Block in the chain is not in the store";
                                "request_root" => ?root
                            );
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
                            error!(
                                self.log,
                                "Error fetching block for peer";
                                "block_root" => ?root,
                                "error" => ?e
                            );
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
}
