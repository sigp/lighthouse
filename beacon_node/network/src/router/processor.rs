use crate::service::NetworkMessage;
use crate::sync::{PeerSyncInfo, SyncMessage};
use beacon_chain::{
    attestation_verification::{
        Error as AttnError, SignatureVerifiedAttestation, VerifiedAggregatedAttestation,
        VerifiedUnaggregatedAttestation,
    },
    BeaconChain, BeaconChainError, BeaconChainTypes, BlockError, BlockProcessingOutcome,
    ForkChoiceError, GossipVerifiedBlock,
};
use eth2_libp2p::rpc::*;
use eth2_libp2p::{NetworkGlobals, PeerId, Request, Response};
use slog::{debug, error, o, trace, warn};
use ssz::Encode;
use std::sync::Arc;
use store::Store;
use tokio::sync::mpsc;
use types::{
    Attestation, ChainSpec, Epoch, EthSpec, Hash256, SignedAggregateAndProof, SignedBeaconBlock,
    Slot,
};

//TODO: Rate limit requests

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
    /// The `RPCHandler` logger.
    log: slog::Logger,
}

impl<T: BeaconChainTypes> Processor<T> {
    /// Instantiate a `Processor` instance
    pub fn new(
        executor: environment::TaskExecutor,
        beacon_chain: Arc<BeaconChain<T>>,
        network_globals: Arc<NetworkGlobals<T::EthSpec>>,
        network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
        log: &slog::Logger,
    ) -> Self {
        let sync_logger = log.new(o!("service"=> "sync"));

        // spawn the sync thread
        let sync_send = crate::sync::manager::spawn(
            executor,
            beacon_chain.clone(),
            network_globals,
            network_send.clone(),
            sync_logger,
        );

        Processor {
            chain: beacon_chain,
            sync_send,
            network: HandlerNetworkContext::new(network_send, log.clone()),
            log: log.clone(),
        }
    }

    fn send_to_sync(&mut self, message: SyncMessage<T::EthSpec>) {
        self.sync_send.send(message).unwrap_or_else(|_| {
            warn!(
                self.log,
                "Could not send message to the sync service";
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
        if let Some(status_message) = status_message(&self.chain) {
            debug!(
                self.log,
                "Sending Status Request";
                "peer" => format!("{:?}", peer_id),
                "fork_digest" => format!("{:?}", status_message.fork_digest),
                "finalized_root" => format!("{:?}", status_message.finalized_root),
                "finalized_epoch" => format!("{:?}", status_message.finalized_epoch),
                "head_root" => format!("{}", status_message.head_root),
                "head_slot" => format!("{}", status_message.head_slot),
            );
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
        request_id: SubstreamId,
        status: StatusMessage,
    ) {
        debug!(
            self.log,
            "Received Status Request";
            "peer" => format!("{:?}", peer_id),
            "fork_digest" => format!("{:?}", status.fork_digest),
            "finalized_root" => format!("{:?}", status.finalized_root),
            "finalized_epoch" => format!("{:?}", status.finalized_epoch),
            "head_root" => format!("{}", status.head_root),
            "head_slot" => format!("{}", status.head_slot),
        );

        // ignore status responses if we are shutting down
        if let Some(status_message) = status_message(&self.chain) {
            // Say status back.
            self.network.send_response(
                peer_id.clone(),
                Response::Status(status_message),
                request_id,
            );
        }

        self.process_status(peer_id, status);
    }

    /// Process a `Status` response from a peer.
    pub fn on_status_response(&mut self, peer_id: PeerId, status: StatusMessage) {
        debug!(
            self.log,
            "Received Status Response";
            "peer_id" => peer_id.to_string(),
            "fork_digest" => format!("{:?}", status.fork_digest),
            "finalized_root" => format!("{:?}", status.finalized_root),
            "finalized_epoch" => format!("{:?}", status.finalized_epoch),
            "head_root" => format!("{}", status.head_root),
            "head_slot" => format!("{}", status.head_slot),
        );

        // Process the status message, without sending back another status.
        self.process_status(peer_id, status);
    }

    /// Process a `Status` message, requesting new blocks if appropriate.
    ///
    /// Disconnects the peer if required.
    fn process_status(&mut self, peer_id: PeerId, status: StatusMessage) {
        let remote = PeerSyncInfo::from(status);
        let local = match PeerSyncInfo::from_chain(&self.chain) {
            Some(local) => local,
            None => {
                return error!(
                    self.log,
                    "Failed to get peer sync info";
                    "msg" => "likely due to head lock contention"
                )
            }
        };

        let start_slot = |epoch: Epoch| epoch.start_slot(T::EthSpec::slots_per_epoch());

        if local.fork_digest != remote.fork_digest {
            // The node is on a different network/fork, disconnect them.
            debug!(
                self.log, "Handshake Failure";
                "peer_id" => peer_id.to_string(),
                "reason" => "incompatible forks",
                "our_fork" => hex::encode(local.fork_digest),
                "their_fork" => hex::encode(remote.fork_digest)
            );

            self.network
                .disconnect(peer_id, GoodbyeReason::IrrelevantNetwork);
        } else if remote.head_slot
            > self.chain.slot().unwrap_or_else(|_| Slot::from(0u64)) + FUTURE_SLOT_TOLERANCE
        {
            // Note: If the slot_clock cannot be read, this will not error. Other system
            // components will deal with an invalid slot clock error.

            // The remotes head is on a slot that is significantly ahead of ours. This could be
            // because they are using a different genesis time, or that theirs or our system
            // clock is incorrect.
            debug!(
            self.log, "Handshake Failure";
            "peer" => format!("{:?}", peer_id),
            "reason" => "different system clocks or genesis time"
            );
            self.network
                .disconnect(peer_id, GoodbyeReason::IrrelevantNetwork);
        } else if remote.finalized_epoch <= local.finalized_epoch
            && remote.finalized_root != Hash256::zero()
            && local.finalized_root != Hash256::zero()
            && self
                .chain
                .root_at_slot(start_slot(remote.finalized_epoch))
                .map(|root_opt| root_opt != Some(remote.finalized_root))
                .unwrap_or_else(|_| false)
        {
            // The remotes finalized epoch is less than or greater than ours, but the block root is
            // different to the one in our chain.
            //
            // Therefore, the node is on a different chain and we should not communicate with them.
            debug!(
                self.log, "Handshake Failure";
                "peer" => format!("{:?}", peer_id),
                "reason" => "different finalized chain"
            );
            self.network
                .disconnect(peer_id, GoodbyeReason::IrrelevantNetwork);
        } else if remote.finalized_epoch < local.finalized_epoch {
            // The node has a lower finalized epoch, their chain is not useful to us. There are two
            // cases where a node can have a lower finalized epoch:
            //
            // ## The node is on the same chain
            //
            // If a node is on the same chain but has a lower finalized epoch, their head must be
            // lower than ours. Therefore, we have nothing to request from them.
            //
            // ## The node is on a fork
            //
            // If a node is on a fork that has a lower finalized epoch, switching to that fork would
            // cause us to revert a finalized block. This is not permitted, therefore we have no
            // interest in their blocks.
            debug!(
                self.log,
                "NaivePeer";
                "peer" => format!("{:?}", peer_id),
                "reason" => "lower finalized epoch"
            );
        } else if self
            .chain
            .store
            .item_exists::<SignedBeaconBlock<T::EthSpec>>(&remote.head_root)
            .unwrap_or_else(|_| false)
        {
            debug!(
                self.log, "Peer with known chain found";
                "peer" => format!("{:?}", peer_id),
                "remote_head_slot" => remote.head_slot,
                "remote_latest_finalized_epoch" => remote.finalized_epoch,
            );

            // If the node's best-block is already known to us and they are close to our current
            // head, treat them as a fully sync'd peer.
            self.send_to_sync(SyncMessage::AddPeer(peer_id, remote));
        } else {
            // The remote node has an equal or great finalized epoch and we don't know it's head.
            //
            // Therefore, there are some blocks between the local finalized epoch and the remote
            // head that are worth downloading.
            debug!(
                self.log, "UsefulPeer";
                "peer" => format!("{:?}", peer_id),
                "local_finalized_epoch" => local.finalized_epoch,
                "remote_latest_finalized_epoch" => remote.finalized_epoch,
            );
            self.send_to_sync(SyncMessage::AddPeer(peer_id, remote));
        }
    }

    /// Handle a `BlocksByRoot` request from the peer.
    pub fn on_blocks_by_root_request(
        &mut self,
        peer_id: PeerId,
        request_id: SubstreamId,
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
                    "peer" => format!("{:?}", peer_id),
                    "request_root" => format!("{:}", root),
                );
            }
        }
        debug!(
            self.log,
            "Received BlocksByRoot Request";
            "peer" => format!("{:?}", peer_id),
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
        request_id: SubstreamId,
        mut req: BlocksByRangeRequest,
    ) {
        debug!(
            self.log,
            "Received BlocksByRange Request";
            "peer" => format!("{:?}", peer_id),
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
            self.network.disconnect(peer_id, GoodbyeReason::Fault);
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

        // pick out the required blocks, ignoring skip-slots and stepping by the step parameter;
        let mut last_block_root = None;
        let block_roots = forwards_block_root_iter
            .take_while(|(_root, slot)| slot.as_u64() < req.start_slot + req.count * req.step)
            // map skip slots to None
            .map(|(root, _slot)| {
                let result = if Some(root) == last_block_root {
                    None
                } else {
                    Some(root)
                };
                last_block_root = Some(root);
                result
            })
            .step_by(req.step as usize)
            .collect::<Vec<_>>();

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

        if blocks_sent < (req.count as usize) {
            debug!(
                self.log,
                "BlocksByRange Response Sent";
                "peer" => format!("{:?}", peer_id),
                "msg" => "Failed to return all requested blocks",
                "start_slot" => req.start_slot,
                "current_slot" => self.chain.slot().unwrap_or_else(|_| Slot::from(0_u64)).as_u64(),
                "requested" => req.count,
                "returned" => blocks_sent);
        } else {
            debug!(
                self.log,
                "Sending BlocksByRange Response";
                "peer" => format!("{:?}", peer_id),
                "start_slot" => req.start_slot,
                "current_slot" => self.chain.slot().unwrap_or_else(|_| Slot::from(0_u64)).as_u64(),
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
            "peer" => format!("{:?}", peer_id),
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
            "peer" => format!("{:?}", peer_id),
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

    /// Template function to be called on a block to determine if the block should be propagated
    /// across the network.
    pub fn should_forward_block(
        &mut self,
        peer_id: &PeerId,
        block: Box<SignedBeaconBlock<T::EthSpec>>,
    ) -> Result<GossipVerifiedBlock<T>, BlockError> {
        let result = self.chain.verify_block_for_gossip(*block.clone());

        if let Err(BlockError::ParentUnknown(_)) = result {
            // if we don't know the parent, start a parent lookup
            // TODO: Modify the return to avoid the block clone.
            self.send_to_sync(SyncMessage::UnknownBlock(peer_id.clone(), block));
        }
        result
    }

    /// Process a gossip message declaring a new block.
    ///
    /// Attempts to apply to block to the beacon chain. May queue the block for later processing.
    ///
    /// Returns a `bool` which, if `true`, indicates we should forward the block to our peers.
    pub fn on_block_gossip(
        &mut self,
        peer_id: PeerId,
        verified_block: GossipVerifiedBlock<T>,
    ) -> bool {
        let block = Box::new(verified_block.block.clone());
        match BlockProcessingOutcome::shim(self.chain.process_block(verified_block)) {
            Ok(outcome) => match outcome {
                BlockProcessingOutcome::Processed { .. } => {
                    trace!(self.log, "Gossipsub block processed";
                            "peer_id" => format!("{:?}",peer_id));

                    // TODO: It would be better if we can run this _after_ we publish the block to
                    // reduce block propagation latency.
                    //
                    // The `MessageHandler` would be the place to put this, however it doesn't seem
                    // to have a reference to the `BeaconChain`. I will leave this for future
                    // works.
                    match self.chain.fork_choice() {
                        Ok(()) => trace!(
                            self.log,
                            "Fork choice success";
                            "location" => "block gossip"
                        ),
                        Err(e) => error!(
                            self.log,
                            "Fork choice failed";
                            "error" => format!("{:?}", e),
                            "location" => "block gossip"
                        ),
                    }
                }
                BlockProcessingOutcome::ParentUnknown { .. } => {
                    // Inform the sync manager to find parents for this block
                    // This should not occur. It should be checked by `should_forward_block`
                    error!(self.log, "Block with unknown parent attempted to be processed";
                            "peer_id" => format!("{:?}",peer_id));
                    self.send_to_sync(SyncMessage::UnknownBlock(peer_id, block));
                }
                other => {
                    warn!(
                        self.log,
                        "Invalid gossip beacon block";
                        "outcome" => format!("{:?}", other),
                        "block root" => format!("{}", block.canonical_root()),
                        "block slot" => block.slot()
                    );
                    trace!(
                        self.log,
                        "Invalid gossip beacon block ssz";
                        "ssz" => format!("0x{}", hex::encode(block.as_ssz_bytes())),
                    );
                }
            },
            Err(_) => {
                // error is logged during the processing therefore no error is logged here
                trace!(
                    self.log,
                    "Erroneous gossip beacon block ssz";
                    "ssz" => format!("0x{}", hex::encode(block.as_ssz_bytes())),
                );
            }
        }
        // TODO: Update with correct block gossip checking
        true
    }

    /// Handle an error whilst verifying an `Attestation` or `SignedAggregateAndProof` from the
    /// network.
    pub fn handle_attestation_verification_failure(
        &mut self,
        peer_id: PeerId,
        beacon_block_root: Hash256,
        attestation_type: &str,
        error: AttnError,
    ) {
        debug!(
            self.log,
            "Invalid attestation from network";
            "block" => format!("{}", beacon_block_root),
            "peer_id" => format!("{:?}", peer_id),
            "type" => format!("{:?}", attestation_type),
        );

        match error {
            AttnError::FutureEpoch { .. }
            | AttnError::PastEpoch { .. }
            | AttnError::FutureSlot { .. }
            | AttnError::PastSlot { .. } => {
                /*
                 * These errors can be triggered by a mismatch between our slot and the peer.
                 *
                 *
                 * The peer has published an invalid consensus message, _only_ if we trust our own clock.
                 */
            }
            AttnError::InvalidSelectionProof { .. } | AttnError::InvalidSignature => {
                /*
                 * These errors are caused by invalid signatures.
                 *
                 * The peer has published an invalid consensus message.
                 */
            }
            AttnError::EmptyAggregationBitfield => {
                /*
                 * The aggregate had no signatures and is therefore worthless.
                 *
                 * Whilst we don't gossip this attestation, this act is **not** a clear
                 * violation of the spec nor indication of fault.
                 *
                 * This may change soon. Reference:
                 *
                 * https://github.com/ethereum/eth2.0-specs/pull/1732
                 */
            }
            AttnError::AggregatorPubkeyUnknown(_) => {
                /*
                 * The aggregator index was higher than any known validator index. This is
                 * possible in two cases:
                 *
                 * 1. The attestation is malformed
                 * 2. The attestation attests to a beacon_block_root that we do not know.
                 *
                 * It should be impossible to reach (2) without triggering
                 * `AttnError::UnknownHeadBlock`, so we can safely assume the peer is
                 * faulty.
                 *
                 * The peer has published an invalid consensus message.
                 */
            }
            AttnError::AggregatorNotInCommittee { .. } => {
                /*
                 * The aggregator index was higher than any known validator index. This is
                 * possible in two cases:
                 *
                 * 1. The attestation is malformed
                 * 2. The attestation attests to a beacon_block_root that we do not know.
                 *
                 * It should be impossible to reach (2) without triggering
                 * `AttnError::UnknownHeadBlock`, so we can safely assume the peer is
                 * faulty.
                 *
                 * The peer has published an invalid consensus message.
                 */
            }
            AttnError::AttestationAlreadyKnown { .. } => {
                /*
                 * The aggregate attestation has already been observed on the network or in
                 * a block.
                 *
                 * The peer is not necessarily faulty.
                 */
            }
            AttnError::AggregatorAlreadyKnown(_) => {
                /*
                 * There has already been an aggregate attestation seen from this
                 * aggregator index.
                 *
                 * The peer is not necessarily faulty.
                 */
            }
            AttnError::PriorAttestationKnown { .. } => {
                /*
                 * We have already seen an attestation from this validator for this epoch.
                 *
                 * The peer is not necessarily faulty.
                 */
            }
            AttnError::ValidatorIndexTooHigh(_) => {
                /*
                 * The aggregator index (or similar field) was higher than the maximum
                 * possible number of validators.
                 *
                 * The peer has published an invalid consensus message.
                 */
            }
            AttnError::UnknownHeadBlock { beacon_block_root } => {
                // Note: its a little bit unclear as to whether or not this block is unknown or
                // just old. See:
                //
                // https://github.com/sigp/lighthouse/issues/1039

                // TODO: Maintain this attestation and re-process once sync completes
                debug!(
                    self.log,
                    "Attestation for unknown block";
                    "peer_id" => format!("{:?}", peer_id),
                    "block" => format!("{}", beacon_block_root)
                );
                // we don't know the block, get the sync manager to handle the block lookup
                self.send_to_sync(SyncMessage::UnknownBlockHash(peer_id, beacon_block_root));
            }
            AttnError::UnknownTargetRoot(_) => {
                /*
                 * The block indicated by the target root is not known to us.
                 *
                 * We should always get `AttnError::UnknwonHeadBlock` before we get this
                 * error, so this means we can get this error if:
                 *
                 * 1. The target root does not represent a valid block.
                 * 2. We do not have the target root in our DB.
                 *
                 * For (2), we should only be processing attestations when we should have
                 * all the available information. Note: if we do a weak-subjectivity sync
                 * it's possible that this situation could occur, but I think it's
                 * unlikely. For now, we will declare this to be an invalid message>
                 *
                 * The peer has published an invalid consensus message.
                 */
            }
            AttnError::BadTargetEpoch => {
                /*
                 * The aggregator index (or similar field) was higher than the maximum
                 * possible number of validators.
                 *
                 * The peer has published an invalid consensus message.
                 */
            }
            AttnError::NoCommitteeForSlotAndIndex { .. } => {
                /*
                 * It is not possible to attest this the given committee in the given slot.
                 *
                 * The peer has published an invalid consensus message.
                 */
            }
            AttnError::NotExactlyOneAggregationBitSet(_) => {
                /*
                 * The unaggregated attestation doesn't have only one signature.
                 *
                 * The peer has published an invalid consensus message.
                 */
            }
            AttnError::AttestsToFutureBlock { .. } => {
                /*
                 * The beacon_block_root is from a higher slot than the attestation.
                 *
                 * The peer has published an invalid consensus message.
                 */
            }
            AttnError::Invalid(_) => {
                /*
                 * The attestation failed the state_processing verification.
                 *
                 * The peer has published an invalid consensus message.
                 */
            }
            AttnError::BeaconChainError(e) => {
                /*
                 * Lighthouse hit an unexpected error whilst processing the attestation. It
                 * should be impossible to trigger a `BeaconChainError` from the network,
                 * so we have a bug.
                 *
                 * It's not clear if the message is invalid/malicious.
                 */
                error!(
                    self.log,
                    "Unable to validate aggregate";
                    "peer_id" => format!("{:?}", peer_id),
                    "error" => format!("{:?}", e),
                );
            }
        }
    }

    pub fn verify_aggregated_attestation_for_gossip(
        &mut self,
        peer_id: PeerId,
        aggregate_and_proof: SignedAggregateAndProof<T::EthSpec>,
    ) -> Option<VerifiedAggregatedAttestation<T>> {
        // This is provided to the error handling function to assist with debugging.
        let beacon_block_root = aggregate_and_proof.message.aggregate.data.beacon_block_root;

        self.chain
            .verify_aggregated_attestation_for_gossip(aggregate_and_proof)
            .map_err(|e| {
                self.handle_attestation_verification_failure(
                    peer_id,
                    beacon_block_root,
                    "aggregated",
                    e,
                )
            })
            .ok()
    }

    pub fn import_aggregated_attestation(
        &mut self,
        peer_id: PeerId,
        verified_attestation: VerifiedAggregatedAttestation<T>,
    ) {
        // This is provided to the error handling function to assist with debugging.
        let beacon_block_root = verified_attestation.attestation().data.beacon_block_root;

        self.apply_attestation_to_fork_choice(
            peer_id.clone(),
            beacon_block_root,
            &verified_attestation,
        );

        if let Err(e) = self.chain.add_to_block_inclusion_pool(verified_attestation) {
            debug!(
                self.log,
                "Attestation invalid for op pool";
                "reason" => format!("{:?}", e),
                "peer" => format!("{:?}", peer_id),
                "beacon_block_root" => format!("{:?}", beacon_block_root)
            )
        }
    }

    pub fn verify_unaggregated_attestation_for_gossip(
        &mut self,
        peer_id: PeerId,
        unaggregated_attestation: Attestation<T::EthSpec>,
    ) -> Option<VerifiedUnaggregatedAttestation<T>> {
        // This is provided to the error handling function to assist with debugging.
        let beacon_block_root = unaggregated_attestation.data.beacon_block_root;

        self.chain
            .verify_unaggregated_attestation_for_gossip(unaggregated_attestation)
            .map_err(|e| {
                self.handle_attestation_verification_failure(
                    peer_id,
                    beacon_block_root,
                    "unaggregated",
                    e,
                )
            })
            .ok()
    }

    pub fn import_unaggregated_attestation(
        &mut self,
        peer_id: PeerId,
        verified_attestation: VerifiedUnaggregatedAttestation<T>,
    ) {
        // This is provided to the error handling function to assist with debugging.
        let beacon_block_root = verified_attestation.attestation().data.beacon_block_root;

        self.apply_attestation_to_fork_choice(
            peer_id.clone(),
            beacon_block_root,
            &verified_attestation,
        );

        if let Err(e) = self
            .chain
            .add_to_naive_aggregation_pool(verified_attestation)
        {
            debug!(
                self.log,
                "Attestation invalid for agg pool";
                "reason" => format!("{:?}", e),
                "peer" => format!("{:?}", peer_id),
                "beacon_block_root" => format!("{:?}", beacon_block_root)
            )
        }
    }

    /// Apply the attestation to fork choice, suppressing errors.
    ///
    /// We suppress the errors when adding an attestation to fork choice since the spec
    /// permits gossiping attestations that are invalid to be applied to fork choice.
    ///
    /// An attestation that is invalid for fork choice can still be included in a block.
    ///
    /// Reference:
    /// https://github.com/ethereum/eth2.0-specs/issues/1408#issuecomment-617599260
    fn apply_attestation_to_fork_choice<'a>(
        &self,
        peer_id: PeerId,
        beacon_block_root: Hash256,
        attestation: &'a impl SignatureVerifiedAttestation<T>,
    ) {
        if let Err(e) = self.chain.apply_attestation_to_fork_choice(attestation) {
            match e {
                BeaconChainError::ForkChoiceError(ForkChoiceError::InvalidAttestation(e)) => {
                    debug!(
                        self.log,
                        "Attestation invalid for fork choice";
                        "reason" => format!("{:?}", e),
                        "peer" => format!("{:?}", peer_id),
                        "beacon_block_root" => format!("{:?}", beacon_block_root)
                    )
                }
                e => error!(
                    self.log,
                    "Error applying attestation to fork choice";
                    "reason" => format!("{:?}", e),
                    "peer" => format!("{:?}", peer_id),
                    "beacon_block_root" => format!("{:?}", beacon_block_root)
                ),
            }
        }
    }
}

/// Build a `StatusMessage` representing the state of the given `beacon_chain`.
pub(crate) fn status_message<T: BeaconChainTypes>(
    beacon_chain: &BeaconChain<T>,
) -> Option<StatusMessage> {
    let head_info = beacon_chain.head_info().ok()?;
    let genesis_validators_root = beacon_chain.genesis_validators_root;

    let fork_digest =
        ChainSpec::compute_fork_digest(head_info.fork.current_version, genesis_validators_root);

    Some(StatusMessage {
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

    fn inform_network(&mut self, msg: NetworkMessage<T>) {
        self.network_send
            .send(msg)
            .unwrap_or_else(|_| warn!(self.log, "Could not send message to the network service"))
    }

    pub fn disconnect(&mut self, peer_id: PeerId, reason: GoodbyeReason) {
        warn!(
            &self.log,
            "Disconnecting peer (RPC)";
            "reason" => format!("{:?}", reason),
            "peer_id" => format!("{:?}", peer_id),
        );
        self.send_processor_request(peer_id.clone(), Request::Goodbye(reason));
        self.inform_network(NetworkMessage::Disconnect { peer_id });
    }

    pub fn send_processor_request(&mut self, peer_id: PeerId, request: Request) {
        self.inform_network(NetworkMessage::SendRequest {
            peer_id,
            request_id: RequestId::Router,
            request,
        })
    }

    pub fn send_response(
        &mut self,
        peer_id: PeerId,
        response: Response<T>,
        stream_id: SubstreamId,
    ) {
        self.inform_network(NetworkMessage::SendResponse {
            peer_id,
            stream_id,
            response,
        })
    }
    pub fn _send_error_response(
        &mut self,
        peer_id: PeerId,
        substream_id: SubstreamId,
        error: RPCResponseErrorCode,
        reason: String,
    ) {
        self.inform_network(NetworkMessage::SendError {
            peer_id,
            error,
            substream_id,
            reason,
        })
    }
}
