use crate::beacon_processor::{
    BeaconProcessor, WorkEvent as BeaconWorkEvent, MAX_WORK_EVENT_QUEUE_LEN,
};
use crate::service::NetworkMessage;
use crate::sync::SyncMessage;
use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2_libp2p::rpc::*;
use eth2_libp2p::{
    MessageId, NetworkGlobals, PeerAction, PeerId, PeerRequestId, Request, Response, SyncInfo,
};
use itertools::process_results;
use slog::{debug, error, o, trace, warn};
use slot_clock::SlotClock;
use std::cmp;
use std::sync::Arc;
use tokio::sync::mpsc;
use types::{
    Attestation, AttesterSlashing, ChainSpec, Epoch, EthSpec, Hash256, ProposerSlashing,
    SignedAggregateAndProof, SignedBeaconBlock, SignedVoluntaryExit, Slot, SubnetId,
};

/// If a block is more than `FUTURE_SLOT_TOLERANCE` slots ahead of our slot clock, we drop it.
/// Otherwise we queue it.
pub(crate) const FUTURE_SLOT_TOLERANCE: u64 = 1;

/// Processes validated messages from the network. It relays necessary data to the syncing thread
/// and processes blocks from the pubsub network.
pub struct Processor<T: BeaconChainTypes> {
    /// A reference to the underlying beacon chain.
    chain: Arc<BeaconChain<T>>,
    /// A channel to the syncing thread.
    sync_send: mpsc::UnboundedSender<SyncMessage<T::EthSpec>>,
    /// A network context to return and handle RPC requests.
    network: HandlerNetworkContext<T::EthSpec>,
    /// A multi-threaded, non-blocking processor for applying messages to the beacon chain.
    beacon_processor_send: mpsc::Sender<BeaconWorkEvent<T::EthSpec>>,
    /// The `RPCHandler` logger.
    log: slog::Logger,
}

impl<T: BeaconChainTypes> Processor<T> {
    /// Instantiate a `Processor` instance
    pub fn new(
        executor: task_executor::TaskExecutor,
        beacon_chain: Arc<BeaconChain<T>>,
        network_globals: Arc<NetworkGlobals<T::EthSpec>>,
        network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
        log: &slog::Logger,
    ) -> Self {
        let sync_logger = log.new(o!("service"=> "sync"));
        let (beacon_processor_send, beacon_processor_receive) =
            mpsc::channel(MAX_WORK_EVENT_QUEUE_LEN);

        // spawn the sync thread
        let sync_send = crate::sync::manager::spawn(
            executor.clone(),
            beacon_chain.clone(),
            network_globals.clone(),
            network_send.clone(),
            beacon_processor_send.clone(),
            sync_logger,
        );

        BeaconProcessor {
            beacon_chain: Arc::downgrade(&beacon_chain),
            network_tx: network_send.clone(),
            sync_tx: sync_send.clone(),
            network_globals,
            executor,
            max_workers: cmp::max(1, num_cpus::get()),
            current_workers: 0,
            log: log.clone(),
        }
        .spawn_manager(beacon_processor_receive);

        Processor {
            chain: beacon_chain,
            sync_send,
            network: HandlerNetworkContext::new(network_send, log.clone()),
            beacon_processor_send,
            log: log.new(o!("service" => "router")),
        }
    }

    fn send_to_sync(&mut self, message: SyncMessage<T::EthSpec>) {
        self.sync_send.send(message).unwrap_or_else(|e| {
            warn!(
                self.log,
                "Could not send message to the sync service";
                "error" => %e,
            )
        });
    }

    /// Handle a peer disconnect.
    ///
    /// Removes the peer from the manager.
    pub fn on_disconnect(&mut self, peer_id: PeerId) {
        self.send_to_sync(SyncMessage::Disconnect(peer_id));
    }

    /// An error occurred during an RPC request. The state is maintained by the sync manager, so
    /// this function notifies the sync manager of the error.
    pub fn on_rpc_error(&mut self, peer_id: PeerId, request_id: RequestId) {
        // Check if the failed RPC belongs to sync
        if let RequestId::Sync(id) = request_id {
            self.send_to_sync(SyncMessage::RPCError(peer_id, id));
        }
    }

    /// Sends a `Status` message to the peer.
    ///
    /// Called when we first connect to a peer, or when the PeerManager determines we need to
    /// re-status.
    pub fn send_status(&mut self, peer_id: PeerId) {
        if let Ok(status_message) = status_message(&self.chain) {
            debug!(self.log, "Sending Status Request"; "peer" => %peer_id, &status_message);
            self.network
                .send_processor_request(peer_id, Request::Status(status_message));
        }
    }

    /// Handle a `Status` request.
    ///
    /// Processes the `Status` from the remote peer and sends back our `Status`.
    pub fn on_status_request(
        &mut self,
        peer_id: PeerId,
        request_id: PeerRequestId,
        status: StatusMessage,
    ) {
        debug!(self.log, "Received Status Request"; "peer_id" => %peer_id, &status);

        // ignore status responses if we are shutting down
        if let Ok(status_message) = status_message(&self.chain) {
            // Say status back.
            self.network.send_response(
                peer_id.clone(),
                Response::Status(status_message),
                request_id,
            );
        }

        if let Err(e) = self.process_status(peer_id, status) {
            error!(self.log, "Could not process status message"; "error" => format!("{:?}", e));
        }
    }

    /// Process a `Status` response from a peer.
    pub fn on_status_response(&mut self, peer_id: PeerId, status: StatusMessage) {
        debug!(self.log, "Received Status Response"; "peer_id" => %peer_id, &status);

        // Process the status message, without sending back another status.
        if let Err(e) = self.process_status(peer_id, status) {
            error!(self.log, "Could not process status message"; "error" => format!("{:?}", e));
        }
    }

    /// Process a `Status` message to determine if a peer is relevant to us. Irrelevant peers are
    /// disconnected; relevant peers are sent to the SyncManager
    fn process_status(
        &mut self,
        peer_id: PeerId,
        remote: StatusMessage,
    ) -> Result<(), BeaconChainError> {
        let local = status_message(&self.chain)?;
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
                .root_at_slot(start_slot(remote.finalized_epoch))
                .map(|root_opt| root_opt != Some(remote.finalized_root))?
        {
            // The remote's finalized epoch is less than or equal to ours, but the block root is
            // different to the one in our chain. Therefore, the node is on a different chain and we
            // should not communicate with them.
            Some("Different finalized chain".to_string())
        } else {
            None
        };

        if let Some(irrelevant_reason) = irrelevant_reason {
            debug!(self.log, "Handshake Failure"; "peer" => %peer_id, "reason" => irrelevant_reason);
            self.network
                .goodbye_peer(peer_id, GoodbyeReason::IrrelevantNetwork);
        } else {
            let info = SyncInfo {
                head_slot: remote.head_slot,
                head_root: remote.head_root,
                finalized_epoch: remote.finalized_epoch,
                finalized_root: remote.finalized_root,
            };
            self.send_to_sync(SyncMessage::AddPeer(peer_id, info));
        }

        Ok(())
    }

    /// Handle a `BlocksByRoot` request from the peer.
    pub fn on_blocks_by_root_request(
        &mut self,
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: BlocksByRootRequest,
    ) {
        let mut send_block_count = 0;
        for root in request.block_roots.iter() {
            if let Ok(Some(block)) = self.chain.store.get_block(root) {
                self.network.send_response(
                    peer_id.clone(),
                    Response::BlocksByRoot(Some(Box::new(block))),
                    request_id,
                );
                send_block_count += 1;
            } else {
                debug!(
                    self.log,
                    "Peer requested unknown block";
                    "peer" => peer_id.to_string(),
                    "request_root" => format!("{:}", root),
                );
            }
        }
        debug!(
            self.log,
            "Received BlocksByRoot Request";
            "peer" => peer_id.to_string(),
            "requested" => request.block_roots.len(),
            "returned" => send_block_count,
        );

        // send stream termination
        self.network
            .send_response(peer_id, Response::BlocksByRoot(None), request_id);
    }

    /// Handle a `BlocksByRange` request from the peer.
    pub fn on_blocks_by_range_request(
        &mut self,
        peer_id: PeerId,
        request_id: PeerRequestId,
        mut req: BlocksByRangeRequest,
    ) {
        debug!(
            self.log,
            "Received BlocksByRange Request";
            "peer_id" => %peer_id,
            "count" => req.count,
            "start_slot" => req.start_slot,
            "step" => req.step,
        );

        // Should not send more than max request blocks
        if req.count > MAX_REQUEST_BLOCKS {
            req.count = MAX_REQUEST_BLOCKS;
        }
        if req.step == 0 {
            warn!(self.log,
                "Peer sent invalid range request";
                "error" => "Step sent was 0");
            self.network.goodbye_peer(peer_id, GoodbyeReason::Fault);
            return;
        }

        let forwards_block_root_iter = match self
            .chain
            .forwards_iter_block_roots(Slot::from(req.start_slot))
        {
            Ok(iter) => iter,
            Err(e) => {
                return error!(
                    self.log,
                    "Unable to obtain root iter";
                    "error" => format!("{:?}", e)
                )
            }
        };

        // Pick out the required blocks, ignoring skip-slots and stepping by the step parameter.
        //
        // NOTE: We don't mind if req.count * req.step overflows as it just ends the iterator early and
        // the peer will get less blocks.
        // The step parameter is quadratically weighted in the filter, so large values should be
        // prevented before reaching this point.
        let mut last_block_root = None;
        let maybe_block_roots = process_results(forwards_block_root_iter, |iter| {
            iter.take_while(|(_, slot)| {
                slot.as_u64() < req.start_slot.saturating_add(req.count * req.step)
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
            .step_by(req.step as usize)
            .collect::<Vec<Option<Hash256>>>()
        });

        let block_roots = match maybe_block_roots {
            Ok(block_roots) => block_roots,
            Err(e) => {
                error!(self.log, "Error during iteration over blocks"; "error" => format!("{:?}", e));
                return;
            }
        };

        // remove all skip slots
        let block_roots = block_roots
            .into_iter()
            .filter_map(|root| root)
            .collect::<Vec<_>>();

        let mut blocks_sent = 0;
        for root in block_roots {
            if let Ok(Some(block)) = self.chain.store.get_block(&root) {
                // Due to skip slots, blocks could be out of the range, we ensure they are in the
                // range before sending
                if block.slot() >= req.start_slot
                    && block.slot() < req.start_slot + req.count * req.step
                {
                    blocks_sent += 1;
                    self.network.send_response(
                        peer_id.clone(),
                        Response::BlocksByRange(Some(Box::new(block))),
                        request_id,
                    );
                }
            } else {
                error!(
                    self.log,
                    "Block in the chain is not in the store";
                    "request_root" => format!("{:}", root),
                );
            }
        }

        let current_slot = self
            .chain
            .slot()
            .unwrap_or_else(|_| self.chain.slot_clock.genesis_slot());

        if blocks_sent < (req.count as usize) {
            debug!(
                self.log,
                "BlocksByRange Response Sent";
                "peer" => peer_id.to_string(),
                "msg" => "Failed to return all requested blocks",
                "start_slot" => req.start_slot,
                "current_slot" => current_slot,
                "requested" => req.count,
                "returned" => blocks_sent);
        } else {
            debug!(
                self.log,
                "Sending BlocksByRange Response";
                "peer" => peer_id.to_string(),
                "start_slot" => req.start_slot,
                "current_slot" => current_slot,
                "requested" => req.count,
                "returned" => blocks_sent);
        }

        // send the stream terminator
        self.network
            .send_response(peer_id, Response::BlocksByRange(None), request_id);
    }

    /// Handle a `BlocksByRange` response from the peer.
    /// A `beacon_block` behaves as a stream which is terminated on a `None` response.
    pub fn on_blocks_by_range_response(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        beacon_block: Option<Box<SignedBeaconBlock<T::EthSpec>>>,
    ) {
        trace!(
            self.log,
            "Received BlocksByRange Response";
            "peer" => peer_id.to_string(),
        );

        if let RequestId::Sync(id) = request_id {
            self.send_to_sync(SyncMessage::BlocksByRangeResponse {
                peer_id,
                request_id: id,
                beacon_block,
            });
        } else {
            debug!(
                self.log,
                "All blocks by range responses should belong to sync"
            );
        }
    }

    /// Handle a `BlocksByRoot` response from the peer.
    pub fn on_blocks_by_root_response(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        beacon_block: Option<Box<SignedBeaconBlock<T::EthSpec>>>,
    ) {
        trace!(
            self.log,
            "Received BlocksByRoot Response";
            "peer" => peer_id.to_string(),
        );

        if let RequestId::Sync(id) = request_id {
            self.send_to_sync(SyncMessage::BlocksByRootResponse {
                peer_id,
                request_id: id,
                beacon_block,
            });
        } else {
            debug!(
                self.log,
                "All Blocks by Root responses should belong to sync"
            )
        }
    }

    /// Process a gossip message declaring a new block.
    ///
    /// Attempts to apply to block to the beacon chain. May queue the block for later processing.
    ///
    /// Returns a `bool` which, if `true`, indicates we should forward the block to our peers.
    pub fn on_block_gossip(
        &mut self,
        message_id: MessageId,
        peer_id: PeerId,
        block: Box<SignedBeaconBlock<T::EthSpec>>,
    ) {
        self.beacon_processor_send
            .try_send(BeaconWorkEvent::gossip_beacon_block(
                message_id, peer_id, block,
            ))
            .unwrap_or_else(|e| {
                error!(
                    &self.log,
                    "Unable to send to gossip processor";
                    "type" => "block gossip",
                    "error" => e.to_string(),
                )
            })
    }

    pub fn on_unaggregated_attestation_gossip(
        &mut self,
        message_id: MessageId,
        peer_id: PeerId,
        unaggregated_attestation: Attestation<T::EthSpec>,
        subnet_id: SubnetId,
        should_process: bool,
    ) {
        self.beacon_processor_send
            .try_send(BeaconWorkEvent::unaggregated_attestation(
                message_id,
                peer_id,
                unaggregated_attestation,
                subnet_id,
                should_process,
            ))
            .unwrap_or_else(|e| {
                error!(
                    &self.log,
                    "Unable to send to gossip processor";
                    "type" => "unaggregated attestation gossip",
                    "error" => e.to_string(),
                )
            })
    }

    pub fn on_aggregated_attestation_gossip(
        &mut self,
        message_id: MessageId,
        peer_id: PeerId,
        aggregate: SignedAggregateAndProof<T::EthSpec>,
    ) {
        self.beacon_processor_send
            .try_send(BeaconWorkEvent::aggregated_attestation(
                message_id, peer_id, aggregate,
            ))
            .unwrap_or_else(|e| {
                error!(
                    &self.log,
                    "Unable to send to gossip processor";
                    "type" => "aggregated attestation gossip",
                    "error" => e.to_string(),
                )
            })
    }

    pub fn on_voluntary_exit_gossip(
        &mut self,
        message_id: MessageId,
        peer_id: PeerId,
        voluntary_exit: Box<SignedVoluntaryExit>,
    ) {
        self.beacon_processor_send
            .try_send(BeaconWorkEvent::gossip_voluntary_exit(
                message_id,
                peer_id,
                voluntary_exit,
            ))
            .unwrap_or_else(|e| {
                error!(
                    &self.log,
                    "Unable to send to gossip processor";
                    "type" => "voluntary exit gossip",
                    "error" => e.to_string(),
                )
            })
    }

    pub fn on_proposer_slashing_gossip(
        &mut self,
        message_id: MessageId,
        peer_id: PeerId,
        proposer_slashing: Box<ProposerSlashing>,
    ) {
        self.beacon_processor_send
            .try_send(BeaconWorkEvent::gossip_proposer_slashing(
                message_id,
                peer_id,
                proposer_slashing,
            ))
            .unwrap_or_else(|e| {
                error!(
                    &self.log,
                    "Unable to send to gossip processor";
                    "type" => "proposer slashing gossip",
                    "error" => e.to_string(),
                )
            })
    }

    pub fn on_attester_slashing_gossip(
        &mut self,
        message_id: MessageId,
        peer_id: PeerId,
        attester_slashing: Box<AttesterSlashing<T::EthSpec>>,
    ) {
        self.beacon_processor_send
            .try_send(BeaconWorkEvent::gossip_attester_slashing(
                message_id,
                peer_id,
                attester_slashing,
            ))
            .unwrap_or_else(|e| {
                error!(
                    &self.log,
                    "Unable to send to gossip processor";
                    "type" => "attester slashing gossip",
                    "error" => e.to_string(),
                )
            })
    }
}

/// Build a `StatusMessage` representing the state of the given `beacon_chain`.
pub(crate) fn status_message<T: BeaconChainTypes>(
    beacon_chain: &BeaconChain<T>,
) -> Result<StatusMessage, BeaconChainError> {
    let head_info = beacon_chain.head_info()?;
    let genesis_validators_root = beacon_chain.genesis_validators_root;

    let fork_digest =
        ChainSpec::compute_fork_digest(head_info.fork.current_version, genesis_validators_root);

    Ok(StatusMessage {
        fork_digest,
        finalized_root: head_info.finalized_checkpoint.root,
        finalized_epoch: head_info.finalized_checkpoint.epoch,
        head_root: head_info.block_root,
        head_slot: head_info.slot,
    })
}

/// Wraps a Network Channel to employ various RPC related network functionality for the
/// processor.
pub struct HandlerNetworkContext<T: EthSpec> {
    /// The network channel to relay messages to the Network service.
    network_send: mpsc::UnboundedSender<NetworkMessage<T>>,
    /// Logger for the `NetworkContext`.
    log: slog::Logger,
}

impl<T: EthSpec> HandlerNetworkContext<T> {
    pub fn new(network_send: mpsc::UnboundedSender<NetworkMessage<T>>, log: slog::Logger) -> Self {
        Self { network_send, log }
    }

    /// Sends a message to the network task.
    fn inform_network(&mut self, msg: NetworkMessage<T>) {
        let msg_r = &format!("{:?}", msg);
        self.network_send
            .send(msg)
            .unwrap_or_else(|e| warn!(self.log, "Could not send message to the network service"; "error" => %e, "message" => msg_r))
    }

    /// Disconnects and ban's a peer, sending a Goodbye request with the associated reason.
    pub fn goodbye_peer(&mut self, peer_id: PeerId, reason: GoodbyeReason) {
        self.inform_network(NetworkMessage::GoodbyePeer { peer_id, reason });
    }

    /// Reports a peer's action, adjusting the peer's score.
    pub fn _report_peer(&mut self, peer_id: PeerId, action: PeerAction) {
        self.inform_network(NetworkMessage::ReportPeer { peer_id, action });
    }

    /// Sends a request to the network task.
    pub fn send_processor_request(&mut self, peer_id: PeerId, request: Request) {
        self.inform_network(NetworkMessage::SendRequest {
            peer_id,
            request_id: RequestId::Router,
            request,
        })
    }

    /// Sends a response to the network task.
    pub fn send_response(&mut self, peer_id: PeerId, response: Response<T>, id: PeerRequestId) {
        self.inform_network(NetworkMessage::SendResponse {
            peer_id,
            id,
            response,
        })
    }

    /// Sends an error response to the network task.
    pub fn _send_error_response(
        &mut self,
        peer_id: PeerId,
        id: PeerRequestId,
        error: RPCResponseErrorCode,
        reason: String,
    ) {
        self.inform_network(NetworkMessage::SendError {
            peer_id,
            error,
            id,
            reason,
        })
    }
}
