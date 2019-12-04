use super::chain::SyncingChain;
use crate::sync::message_processor::{PeerSyncInfo, FUTURE_SLOT_TOLERANCE};
use crate::sync::network_context::SyncNetworkContext;
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockProcessingOutcome};
use eth2_libp2p::rpc::RequestId;
use eth2_libp2p::PeerId;
use slog::{crit, debug, info, trace, warn, Logger};
use std::collections::HashSet;
use std::sync::Weak;
use types::{BeaconBlock, EthSpec};

pub struct RangeSync<T: BeaconChainTypes> {
    /// The beacon chain for processing
    chain: Weak<BeaconChain<T>>,
    /// A network context that provides the ability to send RPC requests/responses and handles a
    /// global request id for the syncing thread.
    //    network: &'a mut SyncNetworkContext,
    /// The current state of the RangeSync
    state: SyncState,
    /// A collection of finalized chains that need to be downloaded.
    finalized_chains: Vec<SyncingChain<T>>,
    /// A collection of head chains that need to be downloaded.
    head_chains: Vec<SyncingChain<T>>,
    /// Known peers to the RangeSync, that need to be re-status'd once finalized chains are
    /// completed.
    awaiting_head_peers: HashSet<PeerId>,
    log: slog::Logger,
}

enum SyncState {
    Finalized,
    Head,
    Idle,
}

impl<T: BeaconChainTypes> RangeSync<T> {
    pub fn new(chain: Weak<BeaconChain<T>>, log: slog::Logger) -> Self {
        RangeSync {
            chain,
            state: SyncState::Idle,
            finalized_chains: Vec::new(),
            head_chains: Vec::new(),
            awaiting_head_peers: HashSet::new(),
            log,
        }
    }

    pub fn add_peer(
        &mut self,
        network: &mut SyncNetworkContext,
        peer_id: PeerId,
        remote: PeerSyncInfo,
    ) {
        // evaluate which chain to sync from

        // determine if we need to run a sync to the nearest finalized state or simply sync to
        // its current head
        let local_info = match self.chain.upgrade() {
            Some(chain) => PeerSyncInfo::from(&chain),
            None => {
                warn!(self.log,
                      "Beacon chain dropped. Peer not considered for sync";
                      "peer_id" => format!("{:?}", peer_id));
                return;
            }
        };

        // convenience variables
        let remote_finalized_slot = remote
            .finalized_epoch
            .start_slot(T::EthSpec::slots_per_epoch());
        let local_finalized_slot = local_info
            .finalized_epoch
            .start_slot(T::EthSpec::slots_per_epoch());

        // firstly, remove any out of date chains
        self.finalized_chains
            .retain(|chain| chain.target_head_slot > local_finalized_slot);
        self.head_chains
            .retain(|chain| chain.target_head_slot > local_info.head_slot);

        if remote.finalized_epoch > local_info.finalized_epoch {
            trace!(self.log, "Peer added - Beginning a finalization sync"; "peer_id" => format!("{:?}", peer_id));
            // finalized chain search

            // if a finalized chain already exists that matches, add this peer to the chain's peer
            // pool.
            if let Some(index) = self.finalized_chains.iter().position(|chain| {
                chain.target_head_root == remote.finalized_root
                    && chain.target_head_slot == remote_finalized_slot
            }) {
                trace!(self.log, "Finalized chain exists, adding peer"; "peer_id" => format!("{:?}", peer_id));
                // add the peer to the chain's peer pool
                self.finalized_chains[index]
                    .peer_pool
                    .insert(peer_id.clone());

                // check if the new peer's addition will favour a new syncing chain.
                if index != 0
                    && self.finalized_chains[index].peer_pool.len()
                        > self.finalized_chains[0].peer_pool.len()
                {
                    // switch to the new syncing chain and stop the old
                    trace!(self.log, "Switching finalized chains to sync"; "peer_id" => format!("{:?}", peer_id));

                    self.finalized_chains[0].stop_syncing();
                    let new_best = self.finalized_chains.swap_remove(index);
                    self.finalized_chains.insert(0, new_best);
                    // start syncing the better chain
                    self.finalized_chains[0].start_syncing(
                        network,
                        local_finalized_slot,
                        &self.log,
                    );
                } else {
                    // no new chain to sync, peer has been added to current syncing chain.
                    // Inform it to request batches from the peer
                    debug!(self.log, "Peer added to chain pool"; "peer_id" => format!("{:?}", peer_id));
                    self.finalized_chains[0].peer_added(network, peer_id, &self.log);
                }
            } else {
                // there is no finalized chain that matches this peer's last finalized target
                // create a new finalized chain
                trace!(self.log, "New finalized chain added to sync"; "peer_id" => format!("{:?}", peer_id));
                self.finalized_chains.push(SyncingChain::new(
                    local_finalized_slot,
                    remote_finalized_slot,
                    remote.finalized_root,
                    peer_id,
                ));

                // This chain will only have a single peer, and will only become the syncing chain
                // if no other chain exists
                if self.finalized_chains.len() == 1 {
                    self.finalized_chains[0].start_syncing(
                        network,
                        local_finalized_slot,
                        &self.log,
                    );
                }
            };
            self.state = SyncState::Finalized;
        } else {
            if !self.finalized_chains.is_empty() {
                // If there are finalized chains to sync, finish these first, before syncing head
                // chains. This allows us to re-sync all known peers
                debug!(self.log, "Peer added - Waiting for finalized sync to complete"; "peer_id" => format!("{:?}", peer_id));
                return;
            }

            // The new peer has the same finalized (earlier filters should prevent a peer with an
            // earlier finalized chain from reaching here).
            trace!(self.log, "New peer added for recent head sync"; "peer_id" => format!("{:?}", peer_id));

            // search if their is a matching head chain, then add the peer to the chain
            if let Some(index) = self.head_chains.iter().position(|chain| {
                chain.target_head_root == remote.head_root
                    && chain.target_head_slot == remote.head_slot
            }) {
                trace!(self.log, "Head chain exists, adding peer to the pool"; "peer_id" => format!("{:?}", peer_id));

                // add the peer to the head's pool
                self.head_chains[index].peer_pool.insert(peer_id.clone());
                self.head_chains[index].peer_added(network, peer_id.clone(), &self.log);
            }
            // There are no other head chains that match this peers status, create a new one, and
            // remove the peer from any old ones
            self.head_chains.iter_mut().for_each(|chain| {
                chain.peer_pool.remove(&peer_id);
            });
            self.head_chains.retain(|chain| !chain.peer_pool.is_empty());

            let mut new_head_chain = SyncingChain::new(
                local_finalized_slot,
                remote.head_slot,
                remote.head_root,
                peer_id,
            );
            // All head chains can sync simultaneously
            new_head_chain.start_syncing(network, local_finalized_slot, &self.log);
            self.head_chains.push(new_head_chain);
            self.state = SyncState::Head;
        }
    }

    pub fn blocks_by_range_response(
        &mut self,
        network: &mut SyncNetworkContext,
        peer_id: PeerId,
        request_id: RequestId,
        beacon_block: Option<BeaconBlock<T::EthSpec>>,
    ) {
        // Find the request. Most likely the first finalized chain (the syncing chain). If there
        // are no finalized chains, then it will be a head chain. At most, there should only be
        // `connected_peers` number of head chains, which should be relatively small and this
        // lookup should not be very expensive. However, we could add an extra index that maps the
        // request id to index of the vector to avoid O(N) searches and O(N) hash lookups.
        // Note to future sync-rewriter/profiler: Michael approves of these O(N) searches.

        let mut update_finalized = false;
        if let Some((index, chain)) = self
            .finalized_chains
            .iter_mut()
            .enumerate()
            .find(|(_, chain)| chain.pending_batches.get(&request_id).is_some())
        {
            // The request was associated with a finalized chain. We do two hashmap lookups to
            // allow for code simplicity and allow the processing to occur on a `SyncingChain`
            // struct.
            // Process the response
            if chain.on_block_response(
                self.chain.clone(),
                network,
                request_id,
                beacon_block,
                &self.log,
            ) {
                // the chain is complete, re-status it's peers and remove it
                chain.status_peers(self.chain.clone(), network);

                // flag to start syncing a new chain as the current completed chain was the
                // syncing chain
                if index == 0 {
                    update_finalized = true;
                }
                self.finalized_chains.swap_remove(index);
            }
        } else if let Some((index, chain)) = self
            .head_chains
            .iter_mut()
            .enumerate()
            .find(|(_, chain)| chain.pending_batches.get(&request_id).is_some())
        {
            // The request was associated with a head chain.
            // Process the completed request for the head chain.
            if chain.on_block_response(
                self.chain.clone(),
                network,
                request_id,
                beacon_block,
                &self.log,
            ) {
                // the chain is complete, re-status it's peers and remove it
                chain.status_peers(self.chain.clone(), network);

                self.head_chains.swap_remove(index);
            }
        } else {
            // The request didn't exist in any `SyncingChain`. Could have been an old request. Log
            // and ignore
            debug!(self.log, "Range response without matching request"; "peer" => format!("{:?}", peer_id), "request_id" => request_id);
        }

        // if a finalized chain has completed, check to see if a new chain needs to start syncing
        if update_finalized {
            // remove any out-dated finalized chains, re statusing their peers.
            let local_info = match self.chain.upgrade() {
                Some(chain) => PeerSyncInfo::from(&chain),
                None => {
                    warn!(self.log,
                          "Beacon chain dropped. Not starting a new sync chain";
                          "peer_id" => format!("{:?}", peer_id));
                    return;
                }
            };
            let beacon_chain = self.chain.clone();
            self.finalized_chains.retain(|chain| {
                if chain.target_head_slot <= local_info.head_slot {
                    chain.status_peers(beacon_chain.clone(), network);
                    false
                } else {
                    true
                }
            });

            // check if there is a new finalized_chain
            if let Some(index) = self
                .finalized_chains
                .iter()
                .enumerate()
                .max_by_key(|(_, chain)| chain.peer_pool.len())
                .map(|(index, _)| index)
            {
                // new syncing chain, begin syncing
                let new_chain = self.finalized_chains.swap_remove(index);
                self.finalized_chains.insert(0, new_chain);
                let local_finalized_slot = local_info
                    .finalized_epoch
                    .start_slot(T::EthSpec::slots_per_epoch());
                self.finalized_chains[0].start_syncing(network, local_finalized_slot, &self.log);
            } else {
                // there is no new finalized_chain, this was the last, re-status all head_peers to
                // begin a head sync
                for peer_id in self.awaiting_head_peers.iter() {
                    network.status_peer(self.chain.clone(), peer_id.clone());
                }
            }
        }
    }

    pub fn is_syncing(&self) -> bool {
        match self.state {
            SyncState::Finalized => true,
            SyncState::Head => true,
            SyncState::Idle => false,
        }
    }

    // if a peer disconnects, re-evaluate which chain to sync
    pub fn peer_disconnect(&mut self, _peer_id: &PeerId) {}

    // TODO: Write this
    pub fn inject_error(&mut self, _peer_id: PeerId, _request_id: RequestId) {}
}

// Helper function to process blocks which only consumes the chain and blocks to process
fn process_blocks<T: BeaconChainTypes>(
    weak_chain: Weak<BeaconChain<T>>,
    blocks: Vec<BeaconBlock<T::EthSpec>>,
    log: &Logger,
) -> Result<(), String> {
    for block in blocks {
        if let Some(chain) = weak_chain.upgrade() {
            let processing_result = chain.process_block(block.clone());

            if let Ok(outcome) = processing_result {
                match outcome {
                    BlockProcessingOutcome::Processed { block_root } => {
                        // The block was valid and we processed it successfully.
                        trace!(
                            log, "Imported block from network";
                            "slot" => block.slot,
                            "block_root" => format!("{}", block_root),
                        );
                    }
                    BlockProcessingOutcome::ParentUnknown { parent } => {
                        // blocks should be sequential and all parents should exist
                        trace!(
                            log, "Parent block is unknown";
                            "parent_root" => format!("{}", parent),
                            "baby_block_slot" => block.slot,
                        );
                        return Err(format!(
                            "Block at slot {} has an unknown parent.",
                            block.slot
                        ));
                    }
                    BlockProcessingOutcome::BlockIsAlreadyKnown => {
                        // this block is already known to us, move to the next
                        debug!(
                            log, "Imported a block that is already known";
                            "block_slot" => block.slot,
                        );
                    }
                    BlockProcessingOutcome::FutureSlot {
                        present_slot,
                        block_slot,
                    } => {
                        if present_slot + FUTURE_SLOT_TOLERANCE >= block_slot {
                            // The block is too far in the future, drop it.
                            trace!(
                                log, "Block is ahead of our slot clock";
                                "msg" => "block for future slot rejected, check your time",
                                "present_slot" => present_slot,
                                "block_slot" => block_slot,
                                "FUTURE_SLOT_TOLERANCE" => FUTURE_SLOT_TOLERANCE,
                            );
                            return Err(format!(
                                "Block at slot {} is too far in the future",
                                block.slot
                            ));
                        } else {
                            // The block is in the future, but not too far.
                            trace!(
                                log, "Block is slightly ahead of our slot clock, ignoring.";
                                "present_slot" => present_slot,
                                "block_slot" => block_slot,
                                "FUTURE_SLOT_TOLERANCE" => FUTURE_SLOT_TOLERANCE,
                            );
                        }
                    }
                    BlockProcessingOutcome::WouldRevertFinalizedSlot { .. } => {
                        trace!(
                            log, "Finalized or earlier block processed";
                            "outcome" => format!("{:?}", outcome),
                        );
                        // block reached our finalized slot or was earlier, move to the next block
                    }
                    BlockProcessingOutcome::GenesisBlock => {
                        trace!(
                            log, "Genesis block was processed";
                            "outcome" => format!("{:?}", outcome),
                        );
                    }
                    _ => {
                        warn!(
                            log, "Invalid block received";
                            "msg" => "peer sent invalid block",
                            "outcome" => format!("{:?}", outcome),
                        );
                        return Err(format!("Invalid block at slot {}", block.slot));
                    }
                }
            } else {
                warn!(
                    log, "BlockProcessingFailure";
                    "msg" => "unexpected condition in processing block.",
                    "outcome" => format!("{:?}", processing_result)
                );
                return Err(format!(
                    "Unexpected block processing error: {:?}",
                    processing_result
                ));
            }
        } else {
            return Ok(()); // terminate early due to dropped beacon chain
        }
    }

    Ok(())
}
