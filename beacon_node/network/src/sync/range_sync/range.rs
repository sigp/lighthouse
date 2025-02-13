//! This contains the logic for the long range (batch) sync strategy.
//!
//! The general premise is to group peers by their self-proclaimed finalized blocks and head
//! blocks. Once grouped, the peers become sources to download a specific `Chain`. A `Chain` is a
//! collection of blocks that terminates at the specified target head.
//!
//! This sync strategy can be separated into two distinct forms:
//!  - Finalized Chain Sync
//!  - Head Chain Sync
//!
//!  ## Finalized chain sync
//!
//!  This occurs when a peer connects that claims to have a finalized head slot that is greater
//!  than our own. In this case, we form a chain from our last finalized epoch, to their claimed
//!  finalized slot. Any peer that also claims to have this last finalized slot is added to a pool
//!  of peers from which batches of blocks may be downloaded. Blocks are downloaded until the
//!  finalized slot of the chain is reached. Once reached, all peers within the pool are sent a
//!  STATUS message to potentially start a head chain sync, or check if further finalized chains
//!  need to be downloaded.
//!
//!  A few interesting notes about finalized chain syncing:
//!  - Only one finalized chain can sync at a time
//!  - The finalized chain with the largest peer pool takes priority.
//!  - As one finalized chain completes, others are checked to see if we they can be continued,
//!    otherwise they are removed.
//!
//!  ## Head Chain Sync
//!
//!  If a peer joins and there is no active finalized chains being synced, and it's head is beyond
//!  our `SLOT_IMPORT_TOLERANCE` a chain is formed starting from this peers finalized epoch (this
//!  has been necessarily downloaded by our node, otherwise we would start a finalized chain sync)
//!  to this peers head slot. Any other peers that match this head slot and head root, are added to
//!  this chain's peer pool, which will be downloaded in parallel.
//!
//!  Unlike finalized chains, head chains can be synced in parallel.
//!
//!  ## Batch Syncing
//!
//!  Each chain is downloaded in batches of blocks. The batched blocks are processed sequentially
//!  and further batches are requested as current blocks are being processed.

use super::chain::{BatchId, ChainId, RemoveChain, SyncingChain};
use super::chain_collection::{ChainCollection, SyncChainStatus};
use super::sync_type::RangeSyncType;
use crate::metrics;
use crate::status::ToStatusMessage;
use crate::sync::network_context::SyncNetworkContext;
use crate::sync::BatchProcessResult;
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_network::rpc::GoodbyeReason;
use lighthouse_network::service::api_types::Id;
use lighthouse_network::{PeerId, SyncInfo};
use lru_cache::LRUTimeCache;
use slog::{crit, debug, trace, warn};
use std::collections::HashMap;
use std::sync::Arc;
use types::{Epoch, EthSpec, Hash256};

/// For how long we store failed finalized chains to prevent retries.
const FAILED_CHAINS_EXPIRY_SECONDS: u64 = 30;

/// The primary object dealing with long range/batch syncing. This contains all the active and
/// non-active chains that need to be processed before the syncing is considered complete. This
/// holds the current state of the long range sync.
pub struct RangeSync<T: BeaconChainTypes> {
    /// The beacon chain for processing.
    beacon_chain: Arc<BeaconChain<T>>,
    /// Last known sync info of our useful connected peers. We use this information to create Head
    /// chains after all finalized chains have ended.
    awaiting_head_peers: HashMap<PeerId, SyncInfo>,
    /// A collection of chains that need to be downloaded. This stores any head or finalized chains
    /// that need to be downloaded.
    chains: ChainCollection<T>,
    /// Chains that have failed and are stored to prevent being retried.
    failed_chains: LRUTimeCache<Hash256>,
    /// The syncing logger.
    log: slog::Logger,
}

impl<T: BeaconChainTypes> RangeSync<T>
where
    T: BeaconChainTypes,
{
    pub fn new(beacon_chain: Arc<BeaconChain<T>>, log: slog::Logger) -> Self {
        RangeSync {
            beacon_chain: beacon_chain.clone(),
            chains: ChainCollection::new(beacon_chain, log.clone()),
            failed_chains: LRUTimeCache::new(std::time::Duration::from_secs(
                FAILED_CHAINS_EXPIRY_SECONDS,
            )),
            awaiting_head_peers: HashMap::new(),
            log,
        }
    }

    #[cfg(test)]
    pub(crate) fn __failed_chains(&mut self) -> Vec<Hash256> {
        self.failed_chains.keys().copied().collect()
    }

    pub fn state(&self) -> SyncChainStatus {
        self.chains.state()
    }

    /// A useful peer has been added. The SyncManager has identified this peer as needing either
    /// a finalized or head chain sync. This processes the peer and starts/resumes any chain that
    /// may need to be synced as a result. A new peer, may increase the peer pool of a finalized
    /// chain, this may result in a different finalized chain from syncing as finalized chains are
    /// prioritised by peer-pool size.
    pub fn add_peer(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        local_info: SyncInfo,
        peer_id: PeerId,
        remote_info: SyncInfo,
    ) {
        // evaluate which chain to sync from

        // determine if we need to run a sync to the nearest finalized state or simply sync to
        // its current head

        // convenience variable
        let remote_finalized_slot = remote_info
            .finalized_epoch
            .start_slot(T::EthSpec::slots_per_epoch());

        // NOTE: A peer that has been re-status'd may now exist in multiple finalized chains. This
        // is OK since we since only one finalized chain at a time.

        // determine which kind of sync to perform and set up the chains
        match RangeSyncType::new(self.beacon_chain.as_ref(), &local_info, &remote_info) {
            RangeSyncType::Finalized => {
                // Make sure we have not recently tried this chain
                if self.failed_chains.contains(&remote_info.finalized_root) {
                    debug!(self.log, "Disconnecting peer that belongs to previously failed chain";
                        "failed_root" => %remote_info.finalized_root, "peer_id" => %peer_id);
                    network.goodbye_peer(peer_id, GoodbyeReason::IrrelevantNetwork);
                    return;
                }

                // Finalized chain search
                debug!(self.log, "Finalization sync peer joined"; "peer_id" => %peer_id);
                self.awaiting_head_peers.remove(&peer_id);

                // Because of our change in finalized sync batch size from 2 to 1 and our transition
                // to using exact epoch boundaries for batches (rather than one slot past the epoch
                // boundary), we need to sync finalized sync to 2 epochs + 1 slot past our peer's
                // finalized slot in order to finalize the chain locally.
                let target_head_slot =
                    remote_finalized_slot + (2 * T::EthSpec::slots_per_epoch()) + 1;

                // Note: We keep current head chains. These can continue syncing whilst we complete
                // this new finalized chain.

                self.chains.add_peer_or_create_chain(
                    local_info.finalized_epoch,
                    remote_info.finalized_root,
                    target_head_slot,
                    peer_id,
                    RangeSyncType::Finalized,
                    network,
                );

                self.chains
                    .update(network, &local_info, &mut self.awaiting_head_peers);
            }
            RangeSyncType::Head => {
                // This peer requires a head chain sync

                if self.chains.is_finalizing_sync() {
                    // If there are finalized chains to sync, finish these first, before syncing head
                    // chains.
                    trace!(self.log, "Waiting for finalized sync to complete";
                        "peer_id" => %peer_id, "awaiting_head_peers" => &self.awaiting_head_peers.len());
                    self.awaiting_head_peers.insert(peer_id, remote_info);
                    return;
                }

                // if the peer existed in any other head chain, remove it.
                self.remove_peer(network, &peer_id);
                self.awaiting_head_peers.remove(&peer_id);

                // The new peer has the same finalized (earlier filters should prevent a peer with an
                // earlier finalized chain from reaching here).

                let start_epoch = std::cmp::min(local_info.head_slot, remote_finalized_slot)
                    .epoch(T::EthSpec::slots_per_epoch());
                self.chains.add_peer_or_create_chain(
                    start_epoch,
                    remote_info.head_root,
                    remote_info.head_slot,
                    peer_id,
                    RangeSyncType::Head,
                    network,
                );
                self.chains
                    .update(network, &local_info, &mut self.awaiting_head_peers);
            }
        }
    }

    /// A `BlocksByRange` response has been received from the network.
    ///
    /// This function finds the chain that made this request. Once found, processes the result.
    /// This request could complete a chain or simply add to its progress.
    pub fn blocks_by_range_response(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        peer_id: PeerId,
        chain_id: ChainId,
        batch_id: BatchId,
        request_id: Id,
        blocks: Vec<RpcBlock<T::EthSpec>>,
    ) {
        // check if this chunk removes the chain
        match self.chains.call_by_id(chain_id, |chain| {
            chain.on_block_response(network, batch_id, &peer_id, request_id, blocks)
        }) {
            Ok((removed_chain, sync_type)) => {
                if let Some((removed_chain, remove_reason)) = removed_chain {
                    self.on_chain_removed(
                        removed_chain,
                        sync_type,
                        remove_reason,
                        network,
                        "block response",
                    );
                }
            }
            Err(_) => {
                trace!(self.log, "BlocksByRange response for removed chain"; "chain" => chain_id)
            }
        }
    }

    pub fn handle_block_process_result(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        chain_id: ChainId,
        batch_id: Epoch,
        result: BatchProcessResult,
    ) {
        // check if this response removes the chain
        match self.chains.call_by_id(chain_id, |chain| {
            chain.on_batch_process_result(network, batch_id, &result)
        }) {
            Ok((None, _sync_type)) => {
                // Chain was found and not removed
            }
            Ok((Some((removed_chain, remove_reason)), sync_type)) => {
                self.on_chain_removed(
                    removed_chain,
                    sync_type,
                    remove_reason,
                    network,
                    "batch processing result",
                );
            }

            Err(_) => {
                trace!(self.log, "BlocksByRange response for removed chain"; "chain" => chain_id)
            }
        }
    }

    /// A peer has disconnected. This removes the peer from any ongoing chains and mappings. A
    /// disconnected peer could remove a chain
    pub fn peer_disconnect(&mut self, network: &mut SyncNetworkContext<T>, peer_id: &PeerId) {
        // if the peer is in the awaiting head mapping, remove it
        self.awaiting_head_peers.remove(peer_id);

        // remove the peer from any peer pool, failing its batches
        self.remove_peer(network, peer_id);
    }

    /// When a peer gets removed, both the head and finalized chains need to be searched to check
    /// which pool the peer is in. The chain may also have a batch or batches awaiting
    /// for this peer. If so we mark the batch as failed. The batch may then hit it's maximum
    /// retries. In this case, we need to remove the chain.
    fn remove_peer(&mut self, network: &mut SyncNetworkContext<T>, peer_id: &PeerId) {
        for (removed_chain, sync_type, remove_reason) in self
            .chains
            .call_all(|chain| chain.remove_peer(peer_id, network))
        {
            self.on_chain_removed(
                removed_chain,
                sync_type,
                remove_reason,
                network,
                "peer removed",
            );
        }
    }

    /// An RPC error has occurred.
    ///
    /// Check to see if the request corresponds to a pending batch. If so, re-request it if possible, if there have
    /// been too many failed attempts for the batch, remove the chain.
    pub fn inject_error(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        peer_id: PeerId,
        batch_id: BatchId,
        chain_id: ChainId,
        request_id: Id,
    ) {
        // check that this request is pending
        match self.chains.call_by_id(chain_id, |chain| {
            chain.inject_error(network, batch_id, &peer_id, request_id)
        }) {
            Ok((removed_chain, sync_type)) => {
                if let Some((removed_chain, remove_reason)) = removed_chain {
                    self.on_chain_removed(
                        removed_chain,
                        sync_type,
                        remove_reason,
                        network,
                        "RPC error",
                    );
                }
            }
            Err(_) => {
                trace!(self.log, "BlocksByRange response for removed chain"; "chain" => chain_id)
            }
        }
    }

    fn on_chain_removed(
        &mut self,
        chain: SyncingChain<T>,
        sync_type: RangeSyncType,
        remove_reason: RemoveChain,
        network: &mut SyncNetworkContext<T>,
        op: &'static str,
    ) {
        if remove_reason.is_critical() {
            crit!(self.log, "Chain removed"; "sync_type" => ?sync_type, &chain, "reason" => ?remove_reason, "op" => op);
        } else {
            debug!(self.log, "Chain removed"; "sync_type" => ?sync_type, &chain, "reason" => ?remove_reason, "op" => op);
        }

        if let RemoveChain::ChainFailed { blacklist, .. } = remove_reason {
            if RangeSyncType::Finalized == sync_type && blacklist {
                warn!(self.log, "Chain failed! Syncing to its head won't be retried for at least the next {} seconds", FAILED_CHAINS_EXPIRY_SECONDS; &chain);
                self.failed_chains.insert(chain.target_head_root);
            }
        }

        metrics::inc_counter_vec_by(
            &metrics::SYNCING_CHAINS_DROPPED_BLOCKS,
            &[sync_type.as_str()],
            chain.pending_blocks() as u64,
        );

        network.status_peers(self.beacon_chain.as_ref(), chain.peers());

        let status = self.beacon_chain.status_message();
        let local = SyncInfo {
            head_slot: status.head_slot,
            head_root: status.head_root,
            finalized_epoch: status.finalized_epoch,
            finalized_root: status.finalized_root,
        };

        // update the state of the collection
        self.chains
            .update(network, &local, &mut self.awaiting_head_peers);
    }

    /// Kickstarts sync.
    pub fn resume(&mut self, network: &mut SyncNetworkContext<T>) {
        for (removed_chain, sync_type, remove_reason) in
            self.chains.call_all(|chain| chain.resume(network))
        {
            self.on_chain_removed(
                removed_chain,
                sync_type,
                remove_reason,
                network,
                "chain resumed",
            );
        }
    }
}
