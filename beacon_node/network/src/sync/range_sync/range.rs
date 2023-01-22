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
use crate::status::ToStatusMessage;
use crate::sync::manager::Id;
use crate::sync::network_context::SyncNetworkContext;
use crate::sync::BatchProcessResult;
use beacon_chain::blob_verification::BlockWrapper;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_network::rpc::GoodbyeReason;
use lighthouse_network::PeerId;
use lighthouse_network::SyncInfo;
use lru_cache::LRUTimeCache;
use slog::{crit, debug, trace, warn};
use std::collections::HashMap;
use std::sync::Arc;
use types::{Epoch, EthSpec, Hash256, Slot};

/// For how long we store failed finalized chains to prevent retries.
const FAILED_CHAINS_EXPIRY_SECONDS: u64 = 30;

/// The primary object dealing with long range/batch syncing. This contains all the active and
/// non-active chains that need to be processed before the syncing is considered complete. This
/// holds the current state of the long range sync.
pub struct RangeSync<T: BeaconChainTypes, C = BeaconChain<T>> {
    /// The beacon chain for processing.
    beacon_chain: Arc<C>,
    /// Last known sync info of our useful connected peers. We use this information to create Head
    /// chains after all finalized chains have ended.
    awaiting_head_peers: HashMap<PeerId, SyncInfo>,
    /// A collection of chains that need to be downloaded. This stores any head or finalized chains
    /// that need to be downloaded.
    chains: ChainCollection<T, C>,
    /// Chains that have failed and are stored to prevent being retried.
    failed_chains: LRUTimeCache<Hash256>,
    /// The syncing logger.
    log: slog::Logger,
}

impl<T: BeaconChainTypes, C> RangeSync<T, C>
where
    C: BlockStorage + ToStatusMessage,
    T: BeaconChainTypes,
{
    pub fn new(beacon_chain: Arc<C>, log: slog::Logger) -> Self {
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

                // Note: We keep current head chains. These can continue syncing whilst we complete
                // this new finalized chain.

                self.chains.add_peer_or_create_chain(
                    local_info.finalized_epoch,
                    remote_info.finalized_root,
                    remote_finalized_slot,
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
        beacon_block: Option<BlockWrapper<T::EthSpec>>,
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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::beacon_processor::WorkEvent as BeaconWorkEvent;
    use crate::service::RequestId;
    use crate::NetworkMessage;
    use beacon_chain::{builder::BeaconChainBuilder, test_utils::test_spec};
    use beacon_chain::{
        builder::Witness, eth1_chain::CachingEth1Backend, parking_lot::RwLock, EngineState,
    };
    use lighthouse_network::{
        rpc::{BlocksByRangeRequest, StatusMessage},
        NetworkGlobals, Request,
    };
    use slog::{o, Drain};
    use sloggers::{null::NullLoggerBuilder, Build};
    use slot_clock::{SlotClock, SystemTimeSlotClock};
    use std::time::{Duration, SystemTime};
    use std::{collections::HashSet, sync::Arc};
    use store::MemoryStore;
    use tokio::sync::mpsc;
    use types::{Hash256, MinimalEthSpec as E};

    const SLOT_DURATION_MILLIS: u64 = 400;

    #[derive(Debug)]
    struct FakeStorage {
        known_blocks: RwLock<HashSet<Hash256>>,
        status: RwLock<StatusMessage>,
    }

    impl Default for FakeStorage {
        fn default() -> Self {
            FakeStorage {
                known_blocks: RwLock::new(HashSet::new()),
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

    impl FakeStorage {
        fn remember_block(&self, block_root: Hash256) {
            self.known_blocks.write().insert(block_root);
        }

        #[allow(dead_code)]
        fn forget_block(&self, block_root: &Hash256) {
            self.known_blocks.write().remove(block_root);
        }
    }

    impl BlockStorage for FakeStorage {
        fn is_block_known(&self, block_root: &store::Hash256) -> bool {
            self.known_blocks.read().contains(block_root)
        }
    }

    impl ToStatusMessage for FakeStorage {
        fn status_message(&self) -> StatusMessage {
            self.status.read().clone()
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
        cx: SyncNetworkContext<TestBeaconChainType>,
        /// To check what the network receives from Range.
        network_rx: mpsc::UnboundedReceiver<NetworkMessage<E>>,
        /// To modify what the network declares about various global variables, in particular about
        /// the sync state of a peer.
        globals: Arc<NetworkGlobals<E>>,
    }

    impl RangeSync<TestBeaconChainType, FakeStorage> {
        fn assert_state(&self, expected_state: RangeSyncType) {
            assert_eq!(
                self.state()
                    .expect("State is ok")
                    .expect("Range is syncing")
                    .0,
                expected_state
            )
        }

        #[allow(dead_code)]
        fn assert_not_syncing(&self) {
            assert!(
                self.state().expect("State is ok").is_none(),
                "Range should not be syncing."
            );
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
        #[track_caller]
        fn grab_request(&mut self, expected_peer: &PeerId) -> (RequestId, BlocksByRangeRequest) {
            if let Ok(NetworkMessage::SendRequest {
                peer_id,
                request: Request::BlocksByRange(request),
                request_id,
            }) = self.network_rx.try_recv()
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
            let finalized_epoch = local_info.finalized_epoch + 2;
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

        #[track_caller]
        fn expect_empty_processor(&mut self) {
            match self.beacon_processor_rx.try_recv() {
                Ok(work) => {
                    panic!("Expected empty processor. Instead got {}", work.work_type());
                }
                Err(e) => match e {
                    mpsc::error::TryRecvError::Empty => {}
                    mpsc::error::TryRecvError::Disconnected => unreachable!("bad coded test?"),
                },
            }
        }

        #[track_caller]
        fn expect_chain_segment(&mut self) {
            match self.beacon_processor_rx.try_recv() {
                Ok(work) => {
                    assert_eq!(work.work_type(), crate::beacon_processor::CHAIN_SEGMENT);
                }
                other => panic!("Expected chain segment process, found {:?}", other),
            }
        }
    }

    fn range(log_enabled: bool) -> (TestRig, RangeSync<TestBeaconChainType, FakeStorage>) {
        let builder = NullLoggerBuilder;
        let db_log = builder.build().expect("should build logger");
        let store = store::HotColdDB::open_ephemeral(
            store::StoreConfig::default(),
            E::default_spec(),
            db_log,
        )
        .unwrap();

        // Initialise a new beacon chain
        let chain = Arc::new(
            BeaconChainBuilder::new(E)
                .custom_spec(test_spec::<E>())
                .store(Arc::new(store))
                .dummy_eth1_backend()
                .expect("should build dummy backend")
                .slot_clock(SystemTimeSlotClock::new(
                    types::Slot::new(0),
                    Duration::from_secs(
                        SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                    ),
                    Duration::from_millis(SLOT_DURATION_MILLIS),
                ))
                .build()
                .expect("should build"),
        );

        let log = build_log(slog::Level::Trace, log_enabled);
        let fake_store = Arc::new(FakeStorage::default());
        let (beacon_processor_tx, beacon_processor_rx) = mpsc::channel(10);
        let range_sync = RangeSync::<TestBeaconChainType, FakeStorage>::new(
            fake_store.clone(),
            log.new(o!("component" => "range")),
        );
        let (network_tx, network_rx) = mpsc::unbounded_channel();
        let globals = Arc::new(NetworkGlobals::new_test_globals(&log));
        let cx = SyncNetworkContext::new(
            network_tx,
            globals.clone(),
            beacon_processor_tx,
            chain,
            log.new(o!("component" => "network_context")),
        );
        let test_rig = TestRig {
            log,
            beacon_processor_rx,
            chain: fake_store,
            cx,
            network_rx,
            globals,
        };
        (test_rig, range_sync)
    }

    #[test]
    fn head_chain_removed_while_finalized_syncing() {
        // NOTE: this is a regression test.
        let (mut rig, mut range) = range(false);

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

    #[test]
    fn state_update_while_purging() {
        // NOTE: this is a regression test.
        let (mut rig, mut range) = range(true);

        // Get a peer with an advanced head
        let (head_peer, local_info, head_info) = rig.head_peer();
        let head_peer_root = head_info.head_root;
        range.add_peer(&mut rig.cx, local_info, head_peer, head_info);
        range.assert_state(RangeSyncType::Head);

        // Sync should have requested a batch, grab the request.
        let _request = rig.grab_request(&head_peer);

        // Now get a peer with an advanced finalized epoch.
        let (finalized_peer, local_info, remote_info) = rig.finalized_peer();
        let finalized_peer_root = remote_info.finalized_root;
        range.add_peer(&mut rig.cx, local_info, finalized_peer, remote_info);
        range.assert_state(RangeSyncType::Finalized);

        // Sync should have requested a batch, grab the request
        let _second_request = rig.grab_request(&finalized_peer);

        // Now the chain knows both chains target roots.
        rig.chain.remember_block(head_peer_root);
        rig.chain.remember_block(finalized_peer_root);

        // Add an additional peer to the second chain to make range update it's status
        let (finalized_peer, local_info, remote_info) = rig.finalized_peer();
        range.add_peer(&mut rig.cx, local_info, finalized_peer, remote_info);
    }

    #[test]
    fn pause_and_resume_on_ee_offline() {
        let (mut rig, mut range) = range(true);

        // add some peers
        let (peer1, local_info, head_info) = rig.head_peer();
        range.add_peer(&mut rig.cx, local_info, peer1, head_info);
        let ((chain1, batch1), id1) = match rig.grab_request(&peer1).0 {
            RequestId::Sync(crate::sync::manager::RequestId::RangeBlocks { id }) => {
                (rig.cx.range_sync_block_response(id, true).unwrap(), id)
            }
            other => panic!("unexpected request {:?}", other),
        };

        // make the ee offline
        rig.cx.update_execution_engine_state(EngineState::Offline);

        // send the response to the request
        range.blocks_by_range_response(&mut rig.cx, peer1, chain1, batch1, id1, None);

        // the beacon processor shouldn't have received any work
        rig.expect_empty_processor();

        // while the ee is offline, more peers might arrive. Add a new finalized peer.
        let (peer2, local_info, finalized_info) = rig.finalized_peer();
        range.add_peer(&mut rig.cx, local_info, peer2, finalized_info);
        let ((chain2, batch2), id2) = match rig.grab_request(&peer2).0 {
            RequestId::Sync(crate::sync::manager::RequestId::RangeBlocks { id }) => {
                (rig.cx.range_sync_block_response(id, true).unwrap(), id)
            }
            other => panic!("unexpected request {:?}", other),
        };

        // send the response to the request
        range.blocks_by_range_response(&mut rig.cx, peer2, chain2, batch2, id2, None);

        // the beacon processor shouldn't have received any work
        rig.expect_empty_processor();

        // make the beacon processor available again.
        rig.cx.update_execution_engine_state(EngineState::Online);

        // now resume range, we should have two processing requests in the beacon processor.
        range.resume(&mut rig.cx);

        rig.expect_chain_segment();
        rig.expect_chain_segment();
    }
}
