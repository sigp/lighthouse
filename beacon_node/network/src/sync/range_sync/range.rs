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
//!  otherwise they are removed.
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

use super::block_storage::BlockStorage;
use super::chain::{BatchId, ChainId, RemoveChain, SyncingChain};
use super::chain_collection::ChainCollection;
use super::sync_type::RangeSyncType;
use crate::beacon_processor::WorkEvent as BeaconWorkEvent;
use crate::status::ToStatusMessage;
use crate::sync::network_context::SyncNetworkContext;
use crate::sync::{BatchProcessResult, RequestId};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_network::PeerId;
use lighthouse_network::SyncInfo;
use slog::{crit, debug, error, trace};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use types::{Epoch, EthSpec, SignedBeaconBlock, Slot};

/// The primary object dealing with long range/batch syncing. This contains all the active and
/// non-active chains that need to be processed before the syncing is considered complete. This
/// holds the current state of the long range sync.
pub struct RangeSync<T: BeaconChainTypes, C = Arc<BeaconChain<T>>> {
    /// The beacon chain for processing.
    beacon_chain: C,
    /// Last known sync info of our useful connected peers. We use this information to create Head
    /// chains after all finalized chains have ended.
    awaiting_head_peers: HashMap<PeerId, SyncInfo>,
    /// A collection of chains that need to be downloaded. This stores any head or finalized chains
    /// that need to be downloaded.
    chains: ChainCollection<T, C>,
    /// A multi-threaded, non-blocking processor for applying messages to the beacon chain.
    beacon_processor_send: mpsc::Sender<BeaconWorkEvent<T>>,
    /// The syncing logger.
    log: slog::Logger,
}

impl<T: BeaconChainTypes, C> RangeSync<T, C>
where
    C: BlockStorage + Clone + ToStatusMessage,
    T: BeaconChainTypes,
{
    pub fn new(
        beacon_chain: C,
        beacon_processor_send: mpsc::Sender<BeaconWorkEvent<T>>,
        log: slog::Logger,
    ) -> Self {
        RangeSync {
            beacon_chain: beacon_chain.clone(),
            chains: ChainCollection::new(beacon_chain, log.clone()),
            awaiting_head_peers: HashMap::new(),
            beacon_processor_send,
            log,
        }
    }

    pub fn state(
        &self,
    ) -> Result<Option<(RangeSyncType, Slot /* from */, Slot /* to */)>, &'static str> {
        self.chains.state()
    }

    /// A useful peer has been added. The SyncManager has identified this peer as needing either
    /// a finalized or head chain sync. This processes the peer and starts/resumes any chain that
    /// may need to be synced as a result. A new peer, may increase the peer pool of a finalized
    /// chain, this may result in a different finalized chain from syncing as finalized chains are
    /// prioritised by peer-pool size.
    pub fn add_peer(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
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
        match RangeSyncType::new(&self.beacon_chain, &local_info, &remote_info) {
            RangeSyncType::Finalized => {
                // Finalized chain search
                debug!(self.log, "Finalization sync peer joined"; "peer_id" => %peer_id);
                self.awaiting_head_peers.remove(&peer_id);

                // Note: We keep current head chains. These can continue syncing whilst we complete
                // this new finalized chain.

                self.chains.add_peer_or_create_chain(
                    local_info.finalized_epoch,
                    remote_info.finalized_root,
                    remote_finalized_slot,
                    peer_id,
                    RangeSyncType::Finalized,
                    &self.beacon_processor_send,
                    network,
                );

                self.chains.update(
                    network,
                    &local_info,
                    &mut self.awaiting_head_peers,
                    &self.beacon_processor_send,
                );
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
                    &self.beacon_processor_send,
                    network,
                );
                self.chains.update(
                    network,
                    &local_info,
                    &mut self.awaiting_head_peers,
                    &self.beacon_processor_send,
                );
            }
        }
    }

    /// A `BlocksByRange` response has been received from the network.
    ///
    /// This function finds the chain that made this request. Once found, processes the result.
    /// This request could complete a chain or simply add to its progress.
    pub fn blocks_by_range_response(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        peer_id: PeerId,
        chain_id: ChainId,
        batch_id: BatchId,
        request_id: RequestId,
        beacon_block: Option<SignedBeaconBlock<T::EthSpec>>,
    ) {
        // check if this chunk removes the chain
        match self.chains.call_by_id(chain_id, |chain| {
            chain.on_block_response(network, batch_id, &peer_id, request_id, beacon_block)
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
        network: &mut SyncNetworkContext<T::EthSpec>,
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
    pub fn peer_disconnect(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        peer_id: &PeerId,
    ) {
        // if the peer is in the awaiting head mapping, remove it
        self.awaiting_head_peers.remove(peer_id);

        // remove the peer from any peer pool, failing its batches
        self.remove_peer(network, peer_id);
    }

    /// When a peer gets removed, both the head and finalized chains need to be searched to check
    /// which pool the peer is in. The chain may also have a batch or batches awaiting
    /// for this peer. If so we mark the batch as failed. The batch may then hit it's maximum
    /// retries. In this case, we need to remove the chain.
    fn remove_peer(&mut self, network: &mut SyncNetworkContext<T::EthSpec>, peer_id: &PeerId) {
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

            // update the state of the collection
        }
    }

    /// An RPC error has occurred.
    ///
    /// Check to see if the request corresponds to a pending batch. If so, re-request it if possible, if there have
    /// been too many failed attempts for the batch, remove the chain.
    pub fn inject_error(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        peer_id: PeerId,
        batch_id: BatchId,
        chain_id: ChainId,
        request_id: RequestId,
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
        network: &mut SyncNetworkContext<T::EthSpec>,
        op: &'static str,
    ) {
        if remove_reason.is_critical() {
            crit!(self.log, "Chain removed"; "sync_type" => ?sync_type, &chain, "reason" => ?remove_reason, "op" => op);
        } else {
            debug!(self.log, "Chain removed"; "sync_type" => ?sync_type, &chain, "reason" => ?remove_reason, "op" => op);
        }

        network.status_peers(self.beacon_chain.clone(), chain.peers());

        let local = match self.beacon_chain.status_message() {
            Ok(status) => SyncInfo {
                head_slot: status.head_slot,
                head_root: status.head_root,
                finalized_epoch: status.finalized_epoch,
                finalized_root: status.finalized_root,
            },
            Err(e) => {
                return error!(self.log, "Failed to get peer sync info";
                    "msg" => "likely due to head lock contention", "err" => ?e)
            }
        };

        // update the state of the collection
        self.chains.update(
            network,
            &local,
            &mut self.awaiting_head_peers,
            &self.beacon_processor_send,
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::NetworkMessage;

    use super::*;
    use beacon_chain::builder::Witness;
    use beacon_chain::eth1_chain::CachingEth1Backend;
    use beacon_chain::parking_lot::RwLock;
    use lighthouse_network::rpc::BlocksByRangeRequest;
    use lighthouse_network::{libp2p, Request};
    use lighthouse_network::{rpc::StatusMessage, NetworkGlobals};
    use slog::{o, Drain};

    use slot_clock::SystemTimeSlotClock;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use store::MemoryStore;
    use types::{Hash256, MinimalEthSpec as E};

    #[derive(Debug)]
    struct FakeStorage {
        is_block_known: AtomicBool,
        status: RwLock<StatusMessage>,
    }

    impl Default for FakeStorage {
        fn default() -> Self {
            FakeStorage {
                is_block_known: AtomicBool::new(false),
                status: RwLock::new(StatusMessage {
                    fork_digest: [0; 4],
                    finalized_root: Hash256::zero(),
                    finalized_epoch: 0usize.into(),
                    head_root: Hash256::zero(),
                    head_slot: 0usize.into(),
                }),
            }
        }
    }

    impl BlockStorage for Arc<FakeStorage> {
        fn is_block_known(&self, _block_root: &store::Hash256) -> bool {
            self.is_block_known
                .load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    impl ToStatusMessage for Arc<FakeStorage> {
        fn status_message(&self) -> Result<StatusMessage, beacon_chain::BeaconChainError> {
            Ok(self.status.read().clone())
        }
    }

    type TestBeaconChainType =
        Witness<SystemTimeSlotClock, CachingEth1Backend<E>, E, MemoryStore<E>, MemoryStore<E>>;

    fn build_log(level: slog::Level, enabled: bool) -> slog::Logger {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();

        if enabled {
            slog::Logger::root(drain.filter_level(level).fuse(), o!())
        } else {
            slog::Logger::root(drain.filter(|_| false).fuse(), o!())
        }
    }

    #[allow(unused)]
    struct TestRig {
        log: slog::Logger,
        /// To check what does sync send to the beacon processor.
        beacon_processor_rx: mpsc::Receiver<BeaconWorkEvent<TestBeaconChainType>>,
        /// To set up different scenarios where sync is told about known/unkown blocks.
        chain: Arc<FakeStorage>,
        /// Needed by range to handle communication with the network.
        cx: SyncNetworkContext<E>,
        /// To check what the network receives from Range.
        network_rx: mpsc::UnboundedReceiver<NetworkMessage<E>>,
        /// To modify what the network declares about various global variables, in particular about
        /// the sync state of a peer.
        globals: Arc<NetworkGlobals<E>>,
    }

    impl RangeSync<TestBeaconChainType, Arc<FakeStorage>> {
        fn assert_state(&self, expected_state: RangeSyncType) {
            assert_eq!(
                self.state()
                    .expect("State is ok")
                    .expect("Range is syncing")
                    .0,
                expected_state
            )
        }
    }

    impl TestRig {
        fn local_info(&self) -> SyncInfo {
            let StatusMessage {
                fork_digest: _,
                finalized_root,
                finalized_epoch,
                head_root,
                head_slot,
            } = self.chain.status.read().clone();
            SyncInfo {
                head_slot,
                head_root,
                finalized_epoch,
                finalized_root,
            }
        }

        /// Reads an BlocksByRange request to a given peer from the network receiver channel.
        fn grab_request(
            &mut self,
            expected_peer: &PeerId,
        ) -> (lighthouse_network::rpc::RequestId, BlocksByRangeRequest) {
            if let Some(NetworkMessage::SendRequest {
                peer_id,
                request: Request::BlocksByRange(request),
                request_id,
            }) = self.network_rx.blocking_recv()
            {
                assert_eq!(&peer_id, expected_peer);
                (request_id, request)
            } else {
                panic!("Should have sent a batch request to the peer")
            }
        }

        /// Produce a head peer
        fn head_peer(
            &self,
        ) -> (
            PeerId,
            SyncInfo, /* Local info */
            SyncInfo, /* Remote info */
        ) {
            let local_info = self.local_info();

            // Get a peer with an advanced head
            let head_root = Hash256::random();
            let head_slot = local_info.head_slot + 1;
            let remote_info = SyncInfo {
                head_root,
                head_slot,
                ..local_info
            };
            let peer_id = PeerId::random();
            (peer_id, local_info, remote_info)
        }

        fn finalized_peer(
            &self,
        ) -> (
            PeerId,
            SyncInfo, /* Local info */
            SyncInfo, /* Remote info */
        ) {
            let local_info = self.local_info();

            let finalized_root = Hash256::random();
            let finalized_epoch = local_info.finalized_epoch + 1;
            let head_slot = finalized_epoch.start_slot(E::slots_per_epoch());
            let head_root = Hash256::random();
            let remote_info = SyncInfo {
                finalized_epoch,
                finalized_root,
                head_slot,
                head_root,
            };

            let peer_id = PeerId::random();
            (peer_id, local_info, remote_info)
        }
    }

    fn range(log_enabled: bool) -> (TestRig, RangeSync<TestBeaconChainType, Arc<FakeStorage>>) {
        let chain = Arc::new(FakeStorage::default());
        let log = build_log(slog::Level::Trace, log_enabled);
        let (beacon_processor_tx, beacon_processor_rx) = mpsc::channel(10);
        let range_sync = RangeSync::<TestBeaconChainType, Arc<FakeStorage>>::new(
            chain.clone(),
            beacon_processor_tx,
            log.new(o!("component" => "range")),
        );
        let (network_tx, network_rx) = mpsc::unbounded_channel();
        let globals = {
            use lighthouse_network::discovery::enr_ext::CombinedKeyExt;
            use lighthouse_network::discv5::enr::CombinedKey;
            use lighthouse_network::discv5::enr::EnrBuilder;
            use lighthouse_network::rpc::methods::{MetaData, MetaDataV2};

            let keypair = libp2p::identity::Keypair::generate_secp256k1();
            let enr_key: CombinedKey = CombinedKey::from_libp2p(&keypair).unwrap();
            let enr = EnrBuilder::new("v4").build(&enr_key).unwrap();
            let globals = NetworkGlobals::new(
                enr,
                9000,
                9000,
                MetaData::V2(MetaDataV2 {
                    seq_number: 0,
                    attnets: Default::default(),
                    syncnets: Default::default(),
                }),
                vec![],
                &log,
            );
            Arc::new(globals)
        };
        let cx = SyncNetworkContext::new(
            network_tx,
            globals.clone(),
            log.new(o!("component" => "network_context")),
        );
        let test_rig = TestRig {
            log,
            beacon_processor_rx,
            chain,
            cx,
            network_rx,
            globals,
        };
        (test_rig, range_sync)
    }

    #[test]
    fn head_chain_removed_while_finalized_syncing() {
        // NOTE: this is a regression test.
        let (mut rig, mut range) = range(true);

        // Get a peer with an advanced head
        let (head_peer, local_info, remote_info) = rig.head_peer();
        range.add_peer(&mut rig.cx, local_info, head_peer, remote_info);
        range.assert_state(RangeSyncType::Head);

        // Sync should have requested a batch, grab the request.
        let _request = rig.grab_request(&head_peer);

        // Now get a peer with an advanced finalized epoch.
        let (finalized_peer, local_info, remote_info) = rig.finalized_peer();
        range.add_peer(&mut rig.cx, local_info, finalized_peer, remote_info);
        range.assert_state(RangeSyncType::Finalized);

        // Sync should have requested a batch, grab the request
        let _second_request = rig.grab_request(&finalized_peer);

        // Fail the head chain by disconnecting the peer.
        range.remove_peer(&mut rig.cx, &head_peer);
        range.assert_state(RangeSyncType::Finalized);
    }
}
