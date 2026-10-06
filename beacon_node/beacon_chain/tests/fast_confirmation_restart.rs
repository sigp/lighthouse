#![cfg(not(debug_assertions))]

use beacon_chain::{
    BeaconChain, BeaconChainTypes, ChainConfig,
    chain_config::FastConfirmationMode,
    test_utils::{
        AttestationStrategy, BeaconChainHarness, BlockStrategy, DiskHarnessType,
        fork_name_from_env, test_spec,
    },
};
use bls::Keypair;
use eth2::types::SignedBlockContentsTuple;
use proto_array::PayloadBlockHash;
use slot_clock::SlotClock;
use std::sync::{Arc, LazyLock};
use store::database::interface::BeaconNodeBackend;
use store::{HotColdDB, StoreConfig};
use tempfile::{TempDir, tempdir};
use types::{BeaconState, EthSpec, Hash256, MinimalEthSpec, SignedExecutionPayloadEnvelope, Slot};

type E = MinimalEthSpec;
type Harness = BeaconChainHarness<DiskHarnessType<E>>;
type Store = Arc<HotColdDB<E, BeaconNodeBackend, BeaconNodeBackend>>;

const VALIDATOR_COUNT: usize = 64;
const WARMUP_SLOTS: u64 = 40;

static KEYPAIRS: LazyLock<Vec<Keypair>> =
    LazyLock::new(|| types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT));

fn store(db: &TempDir) -> Store {
    HotColdDB::open(
        &db.path().join("chain_db"),
        &db.path().join("freezer_db"),
        &db.path().join("blobs_db"),
        |_, _, _| Ok(()),
        StoreConfig {
            prune_payloads: false,
            ..StoreConfig::default()
        },
        test_spec::<E>().into(),
    )
    .unwrap()
}

fn config(fcr: bool, reset_payload_statuses: bool) -> ChainConfig {
    ChainConfig {
        fast_confirmation: if fcr {
            FastConfirmationMode::Enabled
        } else {
            FastConfirmationMode::Disabled
        },
        always_reset_payload_statuses: reset_payload_statuses,
        ..ChainConfig::default()
    }
}

/// The harness owns the mock execution layer and the clock; the node shares both.
fn harness(store: Store) -> Harness {
    let harness = Harness::builder(MinimalEthSpec)
        .spec(store.get_chain_spec().clone())
        .keypairs(KEYPAIRS.to_vec())
        .fresh_disk_store(store)
        .mock_execution_layer()
        .chain_config(config(true, false))
        .build();
    harness.advance_slot();
    harness
}

fn node(store: Store, harness: &Harness, fresh: bool, fcr: bool, reset: bool) -> Harness {
    let builder = Harness::builder(MinimalEthSpec)
        .spec(store.get_chain_spec().clone())
        .keypairs(KEYPAIRS.to_vec());
    let builder = if fresh {
        builder.fresh_disk_store(store)
    } else {
        builder.resumed_disk_store(store)
    };
    builder
        .testing_slot_clock(harness.chain.slot_clock.clone())
        .execution_layer(harness.chain.execution_layer.clone())
        .chain_config(config(fcr, reset))
        .build()
}

/// A pre-Bellatrix block has no execution block hash, so `run_fcr` errors and the node always
/// announces the finalized block. These tests have nothing to check there.
fn pre_bellatrix() -> bool {
    fork_name_from_env().is_some_and(|fork| !fork.bellatrix_enabled())
}

fn validators(n: usize) -> Vec<usize> {
    (0..n).collect()
}

/// The root the node last sent its EL, as the node recorded it.
fn confirmed<T: BeaconChainTypes>(chain: &BeaconChain<T>) -> Option<(Hash256, Slot)> {
    let fcr_mutex = chain.canonical_head.fast_confirmation.as_ref()?;
    let fork_choice = chain.canonical_head.fork_choice_read_lock();
    let root = fcr_mutex.lock().roots.announced_root;
    Some((root, fork_choice.get_block(&root).unwrap().slot))
}

fn finalized<T: BeaconChainTypes>(chain: &BeaconChain<T>) -> Hash256 {
    chain
        .canonical_head
        .fork_choice_read_lock()
        .finalized_checkpoint()
        .root
}

struct Produced {
    slot: Slot,
    root: Hash256,
    contents: SignedBlockContentsTuple<E>,
    envelope: Option<SignedExecutionPayloadEnvelope<E>>,
    post_state: BeaconState<E>,
}

struct Rig {
    harness: Harness,
    node: Option<Harness>,
    node_store: Store,
    _dbs: (TempDir, TempDir),
    blocks: Vec<Produced>,
    /// Confirmed root and slot at the moment the node was stopped.
    stopped: Option<(Hash256, Slot)>,
    /// Highest confirmed slot the node has reached.
    high_water: Slot,
    log: Vec<String>,
}

impl Rig {
    fn new() -> Self {
        let (harness_db, node_db) = (tempdir().unwrap(), tempdir().unwrap());
        let harness = harness(store(&harness_db));
        let node_store = store(&node_db);
        let node = node(node_store.clone(), &harness, true, true, false);
        Self {
            harness,
            node: Some(node),
            node_store,
            _dbs: (harness_db, node_db),
            blocks: vec![],
            stopped: None,
            high_water: Slot::new(0),
            log: vec![],
        }
    }

    fn node(&self) -> &Harness {
        self.node.as_ref().unwrap()
    }

    fn slot(&self) -> Slot {
        self.harness.chain.slot().unwrap()
    }

    /// One slot: tick both nodes, then (unless stalled) the harness proposes, the node imports,
    /// `attesters` attest, both recompute the head.
    async fn step(&mut self, attesters: &[usize], propose: bool) {
        self.harness.advance_slot();
        let slot = self.slot();
        self.recompute("tick").await;
        if !propose {
            return;
        }

        let state = self.harness.get_current_state();
        let (contents, envelope, mut post_state) =
            self.harness.make_block_with_envelope(state, slot).await;
        let root = contents.0.canonical_root();
        let block_hash = self
            .harness
            .process_block(slot, root, contents.clone())
            .await
            .unwrap();
        if let Some(envelope) = &envelope {
            let state_root = contents.0.state_root();
            self.harness
                .process_envelope(root, envelope.clone(), &post_state, state_root)
                .await;
        }
        let produced = Produced {
            slot,
            root,
            contents,
            envelope,
            post_state: post_state.clone(),
        };
        if let Some(node) = &self.node {
            Self::import(node, &produced).await;
        }
        self.blocks.push(produced);

        if !attesters.is_empty() {
            let state_root = post_state.canonical_root().unwrap();
            let attestations = self.harness.make_attestations(
                attesters,
                &post_state,
                state_root,
                block_hash,
                slot,
            );
            if let Some(node) = &self.node {
                node.process_attestations(attestations.clone(), &post_state);
            }
            self.harness.process_attestations(attestations, &post_state);
        }
        self.recompute("slot").await;
    }

    async fn import(node: &Harness, block: &Produced) {
        node.process_block_result(block.contents.clone())
            .await
            .unwrap();
        if let Some(envelope) = &block.envelope {
            let state_root = block.contents.0.state_root();
            node.process_envelope(block.root, envelope.clone(), &block.post_state, state_root)
                .await;
        }
    }

    async fn recompute(&mut self, phase: &str) {
        self.harness.chain.recompute_head_at_current_slot().await;
        if let Some(node) = &self.node {
            node.chain.recompute_head_at_current_slot().await;
        }
        self.observe(phase);
    }

    async fn steps(&mut self, n: u64, attesters: &[usize]) {
        for _ in 0..n {
            self.step(attesters, true).await;
        }
    }

    /// A graceful stop persists like a real shutdown; a crash persists nothing beyond the
    /// chain's own epoch-transition writes (`BeaconChain::drop` would persist, so leak it).
    fn stop(&mut self, graceful: bool) {
        let node = self.node.take().unwrap();
        self.stopped = confirmed(&node.chain);
        if graceful {
            node.chain.persist_fork_choice().unwrap();
            node.chain.persist_op_pool().unwrap();
        } else {
            std::mem::forget(node);
        }
        self.log.push(format!("slot {:>3} stopped", self.slot()));
    }

    /// Boot from the database, run FCR once before any catch-up (as a real boot does), then
    /// import every block after the node's head, as sync would.
    async fn boot(&mut self) {
        self.node = Some(node(
            self.node_store.clone(),
            &self.harness,
            false,
            true,
            false,
        ));
        self.node().chain.recompute_head_at_current_slot().await;
        if let Some((root, slot)) = self.stopped
            && slot == self.slot()
        {
            let (now, _) = confirmed(&self.node().chain).unwrap();
            assert_eq!(now, root, "same slot, same block");
        }
        self.observe("boot");
        let head = self.node().chain.canonical_head.cached_head().head_slot();
        for i in 0..self.blocks.len() {
            if self.blocks[i].slot > head {
                Self::import(self.node(), &self.blocks[i]).await;
                self.observe("catch-up");
            }
        }
    }

    /// The invariant: the node never confirms a slot below its own high-water mark
    /// unless the harness is below it too, and both roots are on the same branch.
    fn observe(&mut self, phase: &str) {
        let Some(node) = &self.node else { return };
        let Some((mine_root, mine)) = confirmed(&node.chain) else {
            return;
        };
        let (harness_root, harness) = confirmed(&self.harness.chain).unwrap();
        let (ancestor, descendant) = if mine <= harness {
            (mine_root, harness_root)
        } else {
            (harness_root, mine_root)
        };
        assert!(
            self.harness
                .chain
                .canonical_head
                .fork_choice_read_lock()
                .is_descendant(ancestor, descendant),
            "confirmed roots on different branches at slot {}",
            self.slot()
        );
        let floor = self.high_water.min(harness);
        let head = node.chain.canonical_head.cached_head().head_slot();
        self.log.push(format!(
            "slot {:>3} {phase:<8} harness={harness:>3} node head={head:>3} confirmed={mine:>3}",
            self.slot()
        ));
        assert!(
            mine >= floor,
            "restart-caused unconfirmation ({phase}): node at {mine}, was {}, harness at {harness}\n{}",
            self.high_water,
            self.log.join("\n")
        );
        // Once caught up the node has at most the harness's votes, so it can never be ahead —
        // except while it still sends the pre-restart root, which the harness may have reverted
        // past, having lost the votes to re-confirm it.
        let pinned = self.stopped.is_some_and(|(root, _)| root == mine_root);
        let harness_head = self.harness.chain.canonical_head.cached_head().head_slot();
        assert!(
            head < harness_head || mine <= harness || pinned,
            "over-confirmation ({phase}): node at {mine}, harness at {harness}\n{}",
            self.log.join("\n")
        );
        self.high_water = self.high_water.max(mine);
    }
}

struct Scenario {
    /// Slot within the epoch at which the node stops.
    at: u64,
    /// Empty slots before the stop, both nodes up.
    stall_before: u64,
    /// Slots the node is down.
    down: u64,
    /// Whether the harness keeps proposing while the node is down.
    chain_continues: bool,
    /// Attesters while the node is down.
    attesters_down: usize,
    graceful: bool,
    /// Attesters for the first epoch after the node is back.
    attesters_after: usize,
    restarts: u64,
}

impl Default for Scenario {
    fn default() -> Self {
        Self {
            at: 4,
            stall_before: 0,
            down: 0,
            chain_continues: true,
            attesters_down: VALIDATOR_COUNT,
            graceful: true,
            attesters_after: VALIDATOR_COUNT,
            restarts: 1,
        }
    }
}

impl Scenario {
    fn at(mut self, slot_in_epoch: u64) -> Self {
        self.at = slot_in_epoch;
        self
    }
    fn down(mut self, slots: u64) -> Self {
        self.down = slots;
        self
    }
    fn stall_before(mut self, slots: u64) -> Self {
        self.stall_before = slots;
        self
    }
    fn chain_stalled(mut self) -> Self {
        self.chain_continues = false;
        self
    }
    fn attesters_down(mut self, n: usize) -> Self {
        self.attesters_down = n;
        self
    }
    fn crash(mut self) -> Self {
        self.graceful = false;
        self
    }
    fn attesters_after(mut self, n: usize) -> Self {
        self.attesters_after = n;
        self
    }
    fn restarts(mut self, n: u64) -> Self {
        self.restarts = n;
        self
    }

    async fn run(self) {
        if pre_bellatrix() {
            return;
        }
        let all = validators(VALIDATOR_COUNT);
        let epoch = E::slots_per_epoch();
        let mut rig = Rig::new();
        rig.steps(WARMUP_SLOTS, &all).await;
        while rig.slot().as_u64() % epoch != self.at {
            rig.step(&all, true).await;
        }
        for _ in 0..self.stall_before {
            rig.step(&all, false).await;
        }
        for _ in 0..self.restarts {
            rig.stop(self.graceful);
            let down = validators(self.attesters_down);
            for _ in 0..self.down {
                rig.step(&down, self.chain_continues).await;
            }
            rig.boot().await;
        }
        rig.steps(epoch, &validators(self.attesters_after)).await;
        // Two epochs: where participation collapsed, both sides can only re-derive at the
        // boundary after a fully attested epoch.
        rig.steps(2 * epoch, &all).await;
        assert_eq!(
            confirmed(&rig.harness.chain),
            confirmed(&rig.node().chain),
            "node did not converge on the harness\n{}",
            rig.log.join("\n")
        );
    }
}

#[tokio::test]
async fn instant_restart_at_epoch_start() {
    Scenario::default().at(0).run().await;
}

#[tokio::test]
async fn instant_restart_mid_epoch() {
    Scenario::default().run().await;
}

/// The votes queued in the epoch's last slot are lost with `PersistedForkChoiceV29`. The
/// pre-restart root does not need them.
#[tokio::test]
async fn instant_restart_at_epoch_end() {
    Scenario::default().at(7).run().await;
}

#[tokio::test]
async fn one_slot_of_downtime() {
    Scenario::default().down(1).run().await;
}

#[tokio::test]
async fn three_slots_of_downtime() {
    Scenario::default().at(2).down(3).run().await;
}

#[tokio::test]
async fn downtime_across_an_epoch_boundary() {
    Scenario::default().at(6).down(4).run().await;
}

/// The guard on the width of the window: twelve slots still leaves the root inside it.
#[tokio::test]
async fn downtime_of_more_than_an_epoch() {
    Scenario::default().down(12).run().await;
}

/// The harness re-confirms at the boundary and reverts; the node slept through that boundary and
/// must run the same check when it comes back rather than keep a root the votes no longer carry.
#[tokio::test]
async fn downtime_across_an_epoch_boundary_while_participation_drops() {
    Scenario::default()
        .at(2)
        .down(8)
        .attesters_down(0)
        .run()
        .await;
}

#[tokio::test]
async fn downtime_while_the_chain_is_stalled() {
    Scenario::default().down(3).chain_stalled().run().await;
}

#[tokio::test]
async fn restart_during_a_chain_stall() {
    Scenario::default()
        .at(2)
        .stall_before(3)
        .down(1)
        .run()
        .await;
}

#[tokio::test]
async fn restart_then_nobody_attests() {
    Scenario::default().down(1).attesters_after(0).run().await;
}

#[tokio::test]
async fn restart_then_half_participation() {
    Scenario::default()
        .down(1)
        .attesters_after(VALIDATOR_COUNT / 2)
        .run()
        .await;
}

#[tokio::test]
async fn two_restarts_in_a_row() {
    Scenario::default().down(1).restarts(2).run().await;
}

/// Boots from the last epoch-transition persist, with the confirmed root it had then.
#[ignore = "needs fork choice persisted every slot: a root newer than its snapshot is not in it"]
#[tokio::test]
async fn crash_instead_of_graceful_shutdown() {
    Scenario::default().down(1).crash().run().await;
}

/// FCR off leaves the persisted root alone. With the chain stalled meanwhile, finality never passes
/// that root, so only its age can reject it — and it must.
#[tokio::test]
async fn re_enabling_fcr_drops_a_stale_root() {
    if pre_bellatrix() {
        return;
    }
    let all = validators(VALIDATOR_COUNT);
    let mut rig = Rig::new();
    rig.steps(WARMUP_SLOTS, &all).await;
    rig.stop(true);
    let (stale, _) = rig.stopped.unwrap();

    rig.node = Some(node(
        rig.node_store.clone(),
        &rig.harness,
        false,
        false,
        false,
    ));
    for _ in 0..4 * E::slots_per_epoch() {
        rig.step(&all, false).await;
    }
    rig.stop(true);

    rig.node = Some(node(
        rig.node_store.clone(),
        &rig.harness,
        false,
        true,
        false,
    ));
    rig.node().chain.recompute_head_at_current_slot().await;

    let finalized = rig
        .node()
        .chain
        .canonical_head
        .fork_choice_read_lock()
        .finalized_checkpoint()
        .root;
    assert_ne!(stale, finalized);
    assert_eq!(
        confirmed(&rig.node().chain).unwrap().0,
        finalized,
        "a root from four epochs ago must not be used"
    );
}

/// FCR off while the chain keeps finalizing leaves both persisted roots behind finality, so neither
/// survives the boot that turns it back on.
#[tokio::test]
async fn re_enabling_fcr_drops_roots_finality_passed() {
    if pre_bellatrix() {
        return;
    }
    let all = validators(VALIDATOR_COUNT);
    let mut rig = Rig::new();
    rig.steps(WARMUP_SLOTS, &all).await;
    rig.stop(true);
    let (stale, _) = rig.stopped.unwrap();

    rig.node = Some(node(
        rig.node_store.clone(),
        &rig.harness,
        false,
        false,
        false,
    ));
    rig.steps(4 * E::slots_per_epoch(), &all).await;
    rig.stop(true);

    rig.node = Some(node(
        rig.node_store.clone(),
        &rig.harness,
        false,
        true,
        false,
    ));
    let chain = &rig.node().chain;
    let finalized = finalized(chain);
    assert!(
        !chain
            .canonical_head
            .fork_choice_read_lock()
            .is_finalized_checkpoint_or_descendant(stale),
        "finality should have passed the root the previous run announced"
    );
    let roots = chain
        .canonical_head
        .fast_confirmation
        .as_ref()
        .unwrap()
        .lock();
    assert_eq!(roots.roots.announced_root, finalized);
    assert_eq!(roots.roots.deepest_announced_root, finalized);
}

/// A `--reset-payload-statuses` boot marks every pre-Gloas block optimistic, and an optimistic
/// block is not confirmed. The EL is the one that lost the statuses, so it may lack the block too.
#[tokio::test]
async fn a_payload_status_reset_drops_the_confirmed_root() {
    if pre_bellatrix() {
        return;
    }
    let all = validators(VALIDATOR_COUNT);
    let mut rig = Rig::new();
    rig.steps(WARMUP_SLOTS, &all).await;
    rig.stop(true);
    let (stopped, _) = rig.stopped.unwrap();
    rig.node = Some(node(
        rig.node_store.clone(),
        &rig.harness,
        false,
        true,
        true,
    ));
    rig.node().chain.recompute_head_at_current_slot().await;
    let (root, _) = confirmed(&rig.node().chain).unwrap();
    assert_ne!(root, stopped);
    assert_eq!(root, finalized(&rig.node().chain));
}

// ---------------------------------------------------------------------------
// Single-chain tests, for what the oracle above cannot state.
// ---------------------------------------------------------------------------

/// A chain that confirmed a block ahead of finality, stopped gracefully, and came back
/// `slots_of_downtime` later. The stopped harness is held for its store, clock and execution layer.
struct Restarted {
    _stopped: Harness,
    node: Harness,
    confirmed_before: Hash256,
    slot_before: Slot,
    _db: TempDir,
}

async fn restart_after(slots_of_downtime: u64) -> Restarted {
    restart_after_warmup(WARMUP_SLOTS, slots_of_downtime).await
}

async fn restart_after_warmup(warmup_slots: u64, slots_of_downtime: u64) -> Restarted {
    let db = tempdir().unwrap();
    let store = store(&db);
    let stopped = harness(store.clone());
    stopped
        .extend_chain(
            warmup_slots as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let (confirmed_before, slot_before) = confirmed(&stopped.chain).unwrap();
    assert_ne!(
        confirmed_before,
        finalized(&stopped.chain),
        "FCR should have confirmed a block ahead of the finalized checkpoint"
    );
    stopped.chain.persist_fork_choice().unwrap();

    let slot_clock = stopped.chain.slot_clock.clone();
    let restart_slot = slot_clock.now().unwrap() + slots_of_downtime;
    slot_clock.set_slot(restart_slot.as_u64());
    let node = node(store, &stopped, false, true, false);
    node.chain.recompute_head_at_current_slot().await;

    Restarted {
        _stopped: stopped,
        node,
        confirmed_before,
        slot_before,
        _db: db,
    }
}

/// The next `forkchoiceUpdated` names that root, so the EL's safe block hash does not regress
/// either, even though the rule itself has gone back to the finalized block.
#[tokio::test]
async fn the_confirmed_root_reaches_the_execution_layer() {
    if pre_bellatrix() {
        return;
    }
    let rig = restart_after(1).await;

    assert_eq!(
        confirmed(&rig.node.chain).unwrap().0,
        rig.confirmed_before,
        "the root confirmed before the restart should still hold"
    );

    let safe_block_hash = rig
        .node
        .chain
        .canonical_head
        .cached_head()
        .forkchoice_update_parameters()
        .justified_hash;
    let expected_hash = match rig
        .node
        .chain
        .canonical_head
        .fork_choice_read_lock()
        .get_block(&rig.confirmed_before)
        .unwrap()
        .checkpoint_payload_block_hash()
    {
        PayloadBlockHash::Hash(hash) => Some(hash),
        PayloadBlockHash::PreMerge => None,
    };
    assert_eq!(safe_block_hash, expected_hash);
}

/// The startup `forkchoiceUpdated` is sent from the cached head, before any recompute runs, so the
/// root from before the restart has to be in there already or the EL's safe block hash regresses.
#[tokio::test]
async fn the_startup_update_sends_the_restored_root() {
    if pre_bellatrix() {
        return;
    }
    let all = validators(VALIDATOR_COUNT);
    let mut rig = Rig::new();
    rig.steps(WARMUP_SLOTS, &all).await;
    rig.stop(true);
    let (stopped, _) = rig.stopped.unwrap();

    rig.node = Some(node(
        rig.node_store.clone(),
        &rig.harness,
        false,
        true,
        false,
    ));
    let chain = &rig.node().chain;
    let expected_hash = match chain
        .canonical_head
        .fork_choice_read_lock()
        .get_block(&stopped)
        .unwrap()
        .checkpoint_payload_block_hash()
    {
        PayloadBlockHash::Hash(hash) => Some(hash),
        PayloadBlockHash::PreMerge => None,
    };
    assert_ne!(
        stopped,
        finalized(chain),
        "the pre-restart root must be ahead of finality for this to test anything"
    );
    assert_eq!(
        chain
            .canonical_head
            .cached_head()
            .forkchoice_update_parameters()
            .justified_hash,
        expected_hash
    );
}

/// A root off the head's chain is dropped: the EL rejects such a `forkchoiceUpdated`.
#[tokio::test]
async fn drops_a_root_that_was_reorged_out() {
    if pre_bellatrix() {
        return;
    }
    // Restart near the epoch end so FCR can recover from observed justification at the
    // next boundary, while still trailing the root confirmed before the restart.
    let rig = restart_after_warmup(WARMUP_SLOTS + E::slots_per_epoch() - 1, 0).await;

    // A fork from the pre-restart root's parent, attested by all, takes the head off that branch.
    let first_slot = rig.node.chain.slot().unwrap();
    rig.node
        .extend_chain(
            2,
            BlockStrategy::ForkCanonicalChainAt {
                previous_slot: rig.slot_before - 1,
                first_slot,
            },
            AttestationStrategy::AllValidators,
        )
        .await;

    assert!(
        !rig.node
            .chain
            .canonical_head
            .fork_choice_read_lock()
            .is_descendant(rig.confirmed_before, rig.node.head_block_root()),
        "the fork should have reorged the pre-restart root out"
    );
    assert!(
        rig.slot_before.epoch(E::slots_per_epoch()) + 2 > rig.node.chain.epoch().unwrap(),
        "the pre-restart root must still be recent, or it would be dropped as stale instead"
    );
    let canonical_head = &rig.node.chain.canonical_head;
    let current_confirmed = canonical_head
        .fast_confirmation
        .as_ref()
        .unwrap()
        .lock()
        .fcr
        .confirmed_root;
    let current_confirmed_slot = canonical_head
        .fork_choice_read_lock()
        .get_block(&current_confirmed)
        .unwrap()
        .slot;
    assert!(
        current_confirmed_slot < rig.slot_before,
        "the rule must not have caught up, or that is what dropped the root"
    );
    assert_ne!(
        current_confirmed,
        finalized(&rig.node.chain),
        "FCR must have recovered ahead of finalized for this to test the fallback"
    );
    assert_eq!(
        confirmed(&rig.node.chain).unwrap().0,
        current_confirmed,
        "a reorged pre-restart root must fall back to the current confirmed root"
    );
}

/// Three epochs down puts the root outside the window: the revert the oracle above has to forbid.
#[tokio::test]
async fn falls_back_to_finalized_after_a_long_downtime() {
    if pre_bellatrix() {
        return;
    }
    let rig = restart_after(3 * E::slots_per_epoch()).await;

    assert_ne!(rig.confirmed_before, finalized(&rig.node.chain));
    assert_eq!(
        confirmed(&rig.node.chain).unwrap().0,
        finalized(&rig.node.chain),
        "a stale pre-restart root must not be used"
    );
}
