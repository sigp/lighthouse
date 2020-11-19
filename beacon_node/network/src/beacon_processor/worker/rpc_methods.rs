use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2_libp2p::rpc::StatusMessage;

use crate::beacon_processor::worker::FUTURE_SLOT_TOLERANCE;
use crate::service::NetworkMessage;
use crate::sync::SyncMessage;
use eth2_libp2p::rpc::*;
use eth2_libp2p::{
    MessageId, NetworkGlobals, PeerAction, PeerId, PeerRequestId, Request, Response, SyncInfo,
};
use itertools::process_results;
use slog::{debug, error, o, trace, warn};
use slot_clock::SlotClock;
use std::cmp;
use types::{
    Attestation, AttesterSlashing, ChainSpec, Epoch, EthSpec, Hash256, ProposerSlashing,
    SignedAggregateAndProof, SignedBeaconBlock, SignedVoluntaryExit, Slot, SubnetId,
};

use super::Worker;

// TODO: move this somewhere else
/// Trait to produce a `StatusMessage`
///
/// NOTE: The purpose of this is simply to obtain a `StatusMessage` from the `BeaconChain` without
/// polluting/coupling the type with RPC concepts.
pub trait ToStatusMessage {
    fn status_message(&self) -> Result<StatusMessage, BeaconChainError>;
}

impl<T: BeaconChainTypes> ToStatusMessage for BeaconChain<T> {
    fn status_message(&self) -> Result<StatusMessage, BeaconChainError> {
        let head_info = self.head_info()?;
        let genesis_validators_root = self.genesis_validators_root;

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
}

impl<T: BeaconChainTypes> Worker<T> {

    /* Auxiliary functions */

    /// Disconnects and ban's a peer, sending a Goodbye request with the associated reason.
    pub fn goodbye_peer(&self, peer_id: PeerId, reason: GoodbyeReason) {
        self.send_network_message(NetworkMessage::GoodbyePeer { peer_id, reason });
    }

    pub fn send_response(
        &mut self,
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

    /* Processing functions */

    /// Process a `Status` message to determine if a peer is relevant to us. Irrelevant peers are
    /// disconnected; relevant peers are sent to the SyncManager.
    fn process_status(
        &self,
        peer_id: PeerId,
        remote: StatusMessage,
    ) -> Result<(), BeaconChainError> {
        let local = self.chain.status_message()?;
        let start_slot = |epoch: Epoch| epoch.start_slot(T::EthSpec::slots_per_epoch());

        let irrelevant_reason = if local.fork_digest != remote.fork_digest {
            // The node is on a different network/fork
            Some(
                format!(
                    "Incompatible forks Ours:{} Theirs:{}",
                    hex::encode(local.fork_digest),
                    hex::encode(remote.fork_digest)
                )
                .as_str(),
            )
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
            Some("Different system clocks or genesis time")
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
            Some("Different finalized chain")
        } else {
            None
        };

        if let Some(irrelevant_reason) = irrelevant_reason {
            debug!(self.log, "Handshake Failure"; "peer" => %peer_id, "reason" => irrelevant_reason);
            self.goodbye_peer(peer_id, GoodbyeReason::IrrelevantNetwork);
        } else {
            let info = SyncInfo {
                head_slot: remote.head_slot,
                head_root: remote.head_root,
                finalized_epoch: remote.finalized_epoch,
                finalized_root: remote.finalized_root,
            };
            self.send_sync_message(SyncMessage::AddPeer(peer_id, info));
        }

        Ok(())
    }

    /// Handle a `BlocksByRoot` request from the peer.
    pub fn on_blocks_by_root_request(
        &self,
        peer_id: PeerId,
        request_id: PeerRequestId,
        request: BlocksByRootRequest,
    ) {
        let mut send_block_count = 0;
        for root in request.block_roots.iter() {
            if let Ok(Some(block)) = self.chain.store.get_block(root) {
                self.send_response(
                    peer_id.clone(),
                    Response::BlocksByRoot(Some(Box::new(block))),
                    request_id,
                );
                send_block_count += 1;
            } else {
                debug!(self.log, "Peer requested unknown block";
                    "peer" => %peer_id,
                    "request_root" => ?root);
            }
        }
        debug!(self.log, "Received BlocksByRoot Request";
            "peer" => %peer_id,
            "requested" => request.block_roots.len(),
            "returned" => send_block_count);

        // send stream termination
        self.send_response(peer_id, Response::BlocksByRoot(None), request_id);
    }

    /// Handle a `BlocksByRange` request from the peer.
    pub fn on_blocks_by_range_request(
        &mut self,
        peer_id: PeerId,
        request_id: PeerRequestId,
        mut req: BlocksByRangeRequest,
    ) {
        debug!(self.log, "Received BlocksByRange Request";
            "peer_id" => %peer_id,
            "count" => req.count,
            "start_slot" => req.start_slot,
            "step" => req.step);

        // Should not send more than max request blocks
        if req.count > MAX_REQUEST_BLOCKS {
            req.count = MAX_REQUEST_BLOCKS;
        }
        if req.step == 0 {
            self.goodbye_peer(peer_id, GoodbyeReason::Fault);
            return warn!(self.log, "Peer sent invalid range request"; "error" => "Step sent was 0");
        }

        let forwards_block_root_iter = match self
            .chain
            .forwards_iter_block_roots(Slot::from(req.start_slot))
        {
            Ok(iter) => iter,
            Err(e) => return error!(self.log, "Unable to obtain root iter"; "error" => ?e),
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
            Err(e) => return error!(self.log, "Error during iteration over blocks"; "error" => ?e),
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
                    self.send_network_message(NetworkMessage::SendResponse {
                        peer_id: peer_id.clone(),
                        response: Response::BlocksByRange(Some(Box::new(block))),
                        id: request_id,
                    });
                }
            } else {
                error!(self.log, "Block in the chain is not in the store";
                    "request_root" => ?root);
            }
        }

        let current_slot = self
            .chain
            .slot()
            .unwrap_or_else(|_| self.chain.slot_clock.genesis_slot());

        if blocks_sent < (req.count as usize) {
            debug!(self.log, "BlocksByRange Response sent";
                "peer" => %peer_id,
                "msg" => "Failed to return all requested blocks",
                "start_slot" => req.start_slot,
                "current_slot" => current_slot,
                "requested" => req.count,
                "returned" => blocks_sent);
        } else {
            debug!(self.log, "BlocksByRange Response sent";
                "peer" => %peer_id,
                "start_slot" => req.start_slot,
                "current_slot" => current_slot,
                "requested" => req.count,
                "returned" => blocks_sent);
        }

        // send the stream terminator
        self.send_network_message(NetworkMessage::SendResponse {
            peer_id,
            response: Response::BlocksByRange(None),
            id: request_id,
        });
    }
}
