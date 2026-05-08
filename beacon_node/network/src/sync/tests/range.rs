//! Range sync tests for `BlocksByRange`, `BlobsByRange`, `DataColumnsByRange`.
//!
//! Tests follow the pattern from `lookups.rs`:
//! ```ignore
//! async fn test_name() {
//!     let mut r = TestRig::default();
//!     r.setup_xyz().await;
//!     r.simulate(SimulateConfig::happy_path()).await;
//!     r.assert_range_sync_completed();
//! }
//! ```
//!
//! Rules:
//! - Tests must be succinct and readable (3-10 lines per test body)
//! - All complex logic lives in helpers (setup, SimulateConfig, assert)
//! - Test bodies must not manually grab requests, send SyncMessages, or do anything overly specific
//! - All tests use `simulate()` if they need peers to fulfill requests
//! - Extend `SimulateConfig` for new range-specific behaviors
//! - Extend `simulate()` to support by_range methods

use super::lookups::SimulateConfig;
use super::*;
use crate::status::ToStatusMessage;
use crate::sync::SyncMessage;
use crate::sync::manager::SLOT_IMPORT_TOLERANCE;
use crate::sync::range_sync::RangeSyncType;
use lighthouse_network::rpc::RPCError;
use lighthouse_network::rpc::methods::StatusMessageV2;
use lighthouse_network::{PeerId, SyncInfo};
use types::{Epoch, EthSpec, Hash256, MinimalEthSpec as E, Slot};

/// MinimalEthSpec has 8 slots per epoch
const SLOTS_PER_EPOCH: usize = 8;

impl TestRig {
    fn add_head_peer(&mut self) -> PeerId {
        let local_info = self.local_info();
        self.add_supernode_peer(SyncInfo {
            head_root: Hash256::random(),
            head_slot: local_info.head_slot + 1 + Slot::new(SLOT_IMPORT_TOLERANCE as u64),
            ..local_info
        })
    }

    fn finalized_remote_info_advanced_by(&self, advanced_epochs: Epoch) -> SyncInfo {
        let local_info = self.local_info();
        let finalized_epoch = local_info.finalized_epoch + advanced_epochs;
        SyncInfo {
            finalized_epoch,
            finalized_root: Hash256::random(),
            head_slot: finalized_epoch.start_slot(E::slots_per_epoch()),
            head_root: Hash256::random(),
            earliest_available_slot: None,
        }
    }

    fn local_info(&self) -> SyncInfo {
        let StatusMessageV2 {
            fork_digest: _,
            finalized_root,
            finalized_epoch,
            head_root,
            head_slot,
            earliest_available_slot,
        } = self.harness.chain.status_message().status_v2();
        SyncInfo {
            head_slot,
            head_root,
            finalized_epoch,
            finalized_root,
            earliest_available_slot: Some(earliest_available_slot),
        }
    }

    fn add_fullnode_peer(&mut self, remote_info: SyncInfo) -> PeerId {
        let peer_id = self.new_connected_peer();
        self.send_sync_message(SyncMessage::AddPeer(peer_id, remote_info));
        peer_id
    }

    fn add_supernode_peer(&mut self, remote_info: SyncInfo) -> PeerId {
        let peer_id = self.new_connected_supernode_peer();
        self.send_sync_message(SyncMessage::AddPeer(peer_id, remote_info));
        peer_id
    }

    fn add_fullnode_peers(&mut self, remote_info: SyncInfo, peer_count: usize) {
        for _ in 0..peer_count {
            let peer = self.new_connected_peer();
            self.send_sync_message(SyncMessage::AddPeer(peer, remote_info.clone()));
        }
    }

    fn assert_state(&self, state: RangeSyncType) {
        assert_eq!(
            self.sync_manager
                .range_sync_state()
                .expect("State is ok")
                .expect("Range should be syncing, there are no chains")
                .0,
            state,
            "not expected range sync state"
        );
    }

    fn assert_no_chains_exist(&self) {
        if let Some(chain) = self.sync_manager.get_range_sync_chains().unwrap() {
            panic!("There still exists a chain {chain:?}");
        }
    }

    fn assert_no_failed_chains(&mut self) {
        assert_eq!(
            self.sync_manager.__range_failed_chains(),
            Vec::<Hash256>::new(),
            "Expected no failed chains"
        )
    }

    // -- Setup helpers --

    /// Head sync: peers whose finalized root/epoch match ours (known to fork choice),
    /// but whose head is ahead. Only head chain is created.
    async fn setup_head_sync(&mut self) {
        self.build_chain(SLOTS_PER_EPOCH).await;
        self.add_head_peer();
        self.assert_state(RangeSyncType::Head);
    }

    /// Finalized sync: peers whose finalized epoch is advanced and head == finalized start slot.
    /// Returns the remote SyncInfo (needed for blacklist tests).
    async fn setup_finalized_sync(&mut self) -> SyncInfo {
        let advanced_epochs = 5;
        self.build_chain(advanced_epochs * SLOTS_PER_EPOCH).await;
        let remote_info = self.finalized_remote_info_advanced_by((advanced_epochs as u64).into());
        self.add_fullnode_peers(remote_info.clone(), 100);
        self.add_supernode_peer(remote_info.clone());
        self.assert_state(RangeSyncType::Finalized);
        remote_info
    }

    /// Finalized-to-head: peers whose finalized is advanced AND head is beyond finalized.
    /// After finalized sync completes, head chains are created from awaiting_head_peers.
    async fn setup_finalized_and_head_sync(&mut self) {
        let finalized_epochs = 5;
        let head_epochs = 7;
        self.build_chain(head_epochs * SLOTS_PER_EPOCH).await;
        let local_info = self.local_info();
        let finalized_epoch = local_info.finalized_epoch + Epoch::new(finalized_epochs as u64);
        let head_slot = Slot::new((head_epochs * SLOTS_PER_EPOCH) as u64);
        let remote_info = SyncInfo {
            finalized_epoch,
            finalized_root: Hash256::random(),
            head_slot,
            head_root: Hash256::random(),
            earliest_available_slot: None,
        };
        self.add_fullnode_peers(remote_info.clone(), 100);
        self.add_supernode_peer(remote_info);
        self.assert_state(RangeSyncType::Finalized);
    }

    /// Finalized sync with only 1 fullnode peer (insufficient custody coverage).
    /// Returns remote_info to pass to `add_remaining_finalized_peers`.
    async fn setup_finalized_sync_insufficient_peers(&mut self) -> SyncInfo {
        let advanced_epochs = 5;
        self.build_chain(advanced_epochs * SLOTS_PER_EPOCH).await;
        let remote_info = self.finalized_remote_info_advanced_by((advanced_epochs as u64).into());
        self.add_fullnode_peer(remote_info.clone());
        self.assert_state(RangeSyncType::Finalized);
        remote_info
    }

    /// Finalized sync where local node already has blocks up to `local_epochs`.
    /// Triggers optimistic start: the chain tries to download a batch at the local head
    /// epoch concurrently with sequential processing from the start.
    async fn setup_finalized_sync_with_local_head(&mut self, local_epochs: usize) {
        let target_epochs = local_epochs + 3; // target beyond local head
        self.build_chain(target_epochs * SLOTS_PER_EPOCH).await;
        self.import_blocks_up_to_slot((local_epochs * SLOTS_PER_EPOCH) as u64)
            .await;
        let remote_info = self.finalized_remote_info_advanced_by((target_epochs as u64).into());
        self.add_fullnode_peers(remote_info.clone(), 100);
        self.add_supernode_peer(remote_info);
        self.assert_state(RangeSyncType::Finalized);
    }

    /// Add enough peers to cover all custody columns (same chain as insufficient setup)
    fn add_remaining_finalized_peers(&mut self, remote_info: SyncInfo) {
        self.add_fullnode_peers(remote_info.clone(), 100);
        self.add_supernode_peer(remote_info);
    }

    // -- Assert helpers --

    /// Assert range sync completed: chains created and removed, all blocks ingested,
    /// finalized epoch advanced, no penalties, no leftover events.
    fn assert_range_sync_completed(&mut self) {
        self.assert_successful_range_sync();
        self.assert_no_failed_chains();
        assert_eq!(
            self.head_slot(),
            self.max_known_slot(),
            "Head slot should match the last built block (all blocks ingested)"
        );
        assert!(
            self.finalized_epoch() > types::Epoch::new(0),
            "Finalized epoch should have advanced past genesis, got {}",
            self.finalized_epoch()
        );
        self.assert_no_penalties();
        self.assert_empty_network();
        self.assert_empty_processor();
    }

    /// Assert head sync completed (no finalization expected for short ranges)
    fn assert_head_sync_completed(&mut self) {
        self.assert_successful_range_sync();
        self.assert_no_failed_chains();
        assert_eq!(
            self.head_slot(),
            self.max_known_slot(),
            "Head slot should match the last built block (all blocks ingested)"
        );
        self.assert_no_penalties();
    }

    /// Assert chain was removed and peers received faulty_chain penalty
    fn assert_range_sync_chain_failed(&mut self) {
        self.assert_no_chains_exist();
        assert!(
            self.penalties.iter().any(|p| p.msg == "faulty_chain"),
            "Expected faulty_chain penalty, got {:?}",
            self.penalties
        );
    }

    /// Assert range sync removed chains (e.g., all peers disconnected)
    fn assert_range_sync_chain_removed(&mut self) {
        self.assert_no_chains_exist();
    }

    /// Assert a new peer with a blacklisted root gets disconnected
    fn assert_peer_blacklisted(&mut self, remote_info: SyncInfo) {
        let new_peer = self.add_supernode_peer(remote_info);
        self.pop_received_network_event(|ev| match ev {
            NetworkMessage::GoodbyePeer { peer_id, .. } if *peer_id == new_peer => Some(()),
            _ => None,
        })
        .expect("Peer with blacklisted root should receive Goodbye");
    }
}

// ============================================================================================
//  Tests
// ============================================================================================

/// Head sync: single peer slightly ahead → download batches → all blocks ingested.
#[tokio::test]
async fn head_sync_completes() {
    let mut r = TestRig::default();
    r.setup_head_sync().await;
    r.simulate(SimulateConfig::happy_path()).await;
    r.assert_head_sync_completed();
    r.assert_head_slot(SLOTS_PER_EPOCH as u64);
}

/// Peers with advanced finalized AND head beyond finalized. Finalized sync completes first,
/// then head chains are created from awaiting_head_peers to sync the remaining gap.
#[tokio::test]
async fn finalized_to_head_transition() {
    let mut r = TestRig::default();
    r.setup_finalized_and_head_sync().await;
    r.simulate(SimulateConfig::happy_path()).await;
    r.assert_range_sync_completed();
    r.assert_head_slot(7 * SLOTS_PER_EPOCH as u64);
}

/// Finalized sync happy path: all batches download and process, head advances to target,
/// finalized epoch advances past genesis.
#[tokio::test]
async fn finalized_sync_completes() {
    let mut r = TestRig::default();
    r.setup_finalized_sync().await;
    r.simulate(SimulateConfig::happy_path()).await;
    r.assert_range_sync_completed();
    r.assert_head_slot(5 * SLOTS_PER_EPOCH as u64);
}

/// First BlocksByRange request gets an RPC error. Batch retries from another peer,
/// sync completes with no penalties (RPC errors are not penalized).
#[tokio::test]
async fn batch_rpc_error_retries() {
    let mut r = TestRig::default();
    r.setup_finalized_sync().await;
    r.simulate(SimulateConfig::happy_path().return_rpc_error(RPCError::UnsupportedProtocol))
        .await;
    r.assert_range_sync_completed();
}

/// Peer returns zero blocks for a BlocksByRange request. Batch retries, sync completes.
#[tokio::test]
async fn batch_peer_returns_empty_then_succeeds() {
    let mut r = TestRig::default();
    r.setup_finalized_sync().await;
    r.simulate(SimulateConfig::happy_path().with_no_range_blocks_n_times(1))
        .await;
    r.assert_successful_range_sync();
}

/// Peer returns zero columns for a DataColumnsByRange request. Batch retries, sync completes.
/// Only exercises column logic on fulu+.
#[tokio::test]
async fn batch_peer_returns_no_columns_then_succeeds() {
    let mut r = TestRig::default();
    r.setup_finalized_sync().await;
    r.simulate(SimulateConfig::happy_path().with_no_range_columns_n_times(1))
        .await;
    r.assert_successful_range_sync();
}

/// Peer returns columns with indices it wasn't asked for → UnrequestedIndex verify error.
/// Batch retries from another peer, sync completes.
#[tokio::test]
async fn batch_peer_returns_wrong_column_indices_then_succeeds() {
    let mut r = TestRig::default();
    r.setup_finalized_sync().await;
    r.simulate(SimulateConfig::happy_path().with_wrong_range_column_indices_n_times(1))
        .await;
    r.assert_successful_range_sync();
}

/// Peer returns columns from a slot outside the requested range → UnrequestedSlot verify error.
/// Batch retries from another peer, sync completes.
#[tokio::test]
async fn batch_peer_returns_wrong_column_slots_then_succeeds() {
    let mut r = TestRig::default();
    r.setup_finalized_sync().await;
    r.simulate(SimulateConfig::happy_path().with_wrong_range_column_slots_n_times(1))
        .await;
    r.assert_successful_range_sync();
}

/// PeerDAS: peer returns only half the requested columns. Block-sidecar coupling detects
/// missing columns → CouplingError::DataColumnPeerFailure → retry_partial_batch from other peers.
#[tokio::test]
async fn batch_peer_returns_partial_columns_then_succeeds() {
    let mut r = TestRig::default();
    if !r.fork_name.fulu_enabled() {
        return;
    }
    r.setup_finalized_sync().await;
    r.simulate(SimulateConfig::happy_path().with_partial_range_columns_n_times(1))
        .await;
    r.assert_successful_range_sync();
}

/// Batch processing returns NonFaultyFailure (e.g. transient error). Batch goes back to
/// AwaitingDownload, retries without penalty, sync completes.
#[tokio::test]
async fn batch_non_faulty_failure_retries() {
    let mut r = TestRig::default();
    r.setup_finalized_sync().await;
    r.simulate(SimulateConfig::happy_path().with_range_non_faulty_failures(1))
        .await;
    r.assert_range_sync_completed();
}

/// Batch processing returns FaultyFailure once. Peer penalized with "faulty_batch",
/// batch redownloaded from a different peer, sync completes.
#[tokio::test]
async fn batch_faulty_failure_redownloads() {
    let mut r = TestRig::default();
    r.setup_finalized_sync().await;
    r.simulate(SimulateConfig::happy_path().with_range_faulty_failures(1))
        .await;
    r.assert_successful_range_sync();
    r.assert_penalties_of_type("faulty_batch");
}

/// Batch processing fails MAX_BATCH_PROCESSING_ATTEMPTS (3) times with FaultyFailure.
/// Chain removed, all peers penalized with "faulty_chain".
#[tokio::test]
async fn batch_max_failures_removes_chain() {
    let mut r = TestRig::default();
    r.setup_finalized_sync().await;
    r.simulate(SimulateConfig::happy_path().with_range_faulty_failures(3))
        .await;
    r.assert_range_sync_chain_failed();
}

/// Chain fails via max faulty retries → finalized root added to failed_chains LRU.
/// A new peer advertising the same finalized root gets disconnected with GoodbyeReason.
#[tokio::test]
async fn failed_chain_blacklisted() {
    let mut r = TestRig::default();
    let remote_info = r.setup_finalized_sync().await;
    r.simulate(SimulateConfig::happy_path().with_range_faulty_failures(3))
        .await;
    r.assert_range_sync_chain_failed();
    r.assert_peer_blacklisted(remote_info);
}

/// All peers disconnect before any request is fulfilled → chain removed (EmptyPeerPool).
#[tokio::test]
async fn all_peers_disconnect_removes_chain() {
    let mut r = TestRig::default();
    r.setup_finalized_sync().await;
    r.simulate(SimulateConfig::happy_path().with_disconnect_after_range_requests(0))
        .await;
    r.assert_range_sync_chain_removed();
}

/// Peers disconnect after 1 request is served. Remaining in-flight responses arrive
/// for a chain that no longer exists — verified as a no-op (no crash).
#[tokio::test]
async fn late_response_for_removed_chain() {
    let mut r = TestRig::default();
    r.setup_finalized_sync().await;
    r.simulate(SimulateConfig::happy_path().with_disconnect_after_range_requests(1))
        .await;
    r.assert_range_sync_chain_removed();
}

/// Execution engine goes offline at sync start. Batch responses complete but processing
/// is paused. After 2 responses, EE comes back online, queued batches process, sync completes.
#[tokio::test]
async fn ee_offline_then_online_resumes_sync() {
    let mut r = TestRig::default();
    r.setup_finalized_sync().await;
    r.simulate(SimulateConfig::happy_path().with_ee_offline_for_n_range_responses(2))
        .await;
    r.assert_range_sync_completed();
}

/// Local node already has blocks up to epoch 3. Finalized sync starts targeting epoch 6.
/// The chain uses optimistic start: downloads a batch at the local head epoch concurrently
/// with sequential processing from the start. All blocks ingested.
#[tokio::test]
async fn finalized_sync_with_local_head_partial() {
    let mut r = TestRig::default();
    r.setup_finalized_sync_with_local_head(3).await;
    r.simulate(SimulateConfig::happy_path()).await;
    r.assert_range_sync_completed();
}

/// Local node has all blocks except the last one. Finalized sync only needs to fill the
/// final gap. Tests optimistic start where local head is near the target.
#[tokio::test]
async fn finalized_sync_with_local_head_near_target() {
    let mut r = TestRig::default();
    let target_epochs = 5;
    let local_slots = (target_epochs * SLOTS_PER_EPOCH) - 1; // all blocks except last
    r.build_chain(target_epochs * SLOTS_PER_EPOCH).await;
    r.import_blocks_up_to_slot(local_slots as u64).await;
    let remote_info = r.finalized_remote_info_advanced_by((target_epochs as u64).into());
    r.add_fullnode_peers(remote_info.clone(), 100);
    r.add_supernode_peer(remote_info);
    r.assert_state(RangeSyncType::Finalized);
    r.simulate(SimulateConfig::happy_path()).await;
    r.assert_range_sync_completed();
    r.assert_head_slot((target_epochs * SLOTS_PER_EPOCH) as u64);
}

/// PeerDAS only: single fullnode peer doesn't cover all custody columns → no requests sent.
/// Once enough fullnodes + a supernode arrive, sync proceeds and completes.
#[tokio::test]
async fn not_enough_custody_peers_then_peers_arrive() {
    let mut r = TestRig::default();
    if !r.fork_name.fulu_enabled() {
        return;
    }
    let remote_info = r.setup_finalized_sync_insufficient_peers().await;
    r.assert_empty_network();
    r.add_remaining_finalized_peers(remote_info);
    r.simulate(SimulateConfig::happy_path()).await;
    r.assert_range_sync_completed();
}
