/// ERA file consumer + producer tests using minimal preset test vectors.
///
/// Test vectors: 13 ERA files from a Nimbus minimal testnet.
/// - Electra from genesis, Fulu at epoch 100000
/// - SLOTS_PER_HISTORICAL_ROOT = 64 (one ERA = 64 slots = 8 epochs)
/// - 13 ERA files covering 832 slots, 767 blocks, 1024 validators
///
/// All subtests run from a single #[test] to avoid nextest download races
/// (same pattern as slashing_protection/tests/interop.rs).
use super::consumer::{EraFileDir, EraImportTrust};
use super::store_init::init_genesis_store;
use crate::beacon_chain::WhenSlotSkipped;
use crate::test_utils::BeaconChainHarness;
use reth_era::common::file_ops::StreamReader;
use serde::Deserialize;
use slot_clock::{SlotClock, TestingSlotClock};
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use store::{DBColumn, HotColdDB, KeyValueStore, StoreConfig};
use types::{
    BeaconState, ChainSpec, Config, EthSpec, Hash256, MinimalEthSpec, SignedBeaconBlock, Slot,
};

const MAX_ERA: u64 = 12;

#[derive(Deserialize)]
struct Metadata {
    head_slot: u64,
    head_root: String,
    era_count: u64,
}

static TEST_VECTORS_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("era_test_vectors");
    let make_output = std::process::Command::new("make")
        .current_dir(&dir)
        .output()
        .expect("need `make` to download ERA test vectors");
    if !make_output.status.success() {
        eprintln!("{}", String::from_utf8_lossy(&make_output.stderr));
        panic!("Running `make` for ERA test vectors failed, see above");
    }
    dir.join("vectors")
});

fn vectors() -> &'static PathBuf {
    &TEST_VECTORS_DIR
}

fn era_path() -> PathBuf {
    vectors().join("era")
}

fn load_spec() -> ChainSpec {
    let yaml = std::fs::read_to_string(vectors().join("config.yaml")).expect("read config.yaml");
    let config: Config = yaml_serde::from_str(&yaml).expect("parse config");
    config
        .apply_to_chain_spec::<MinimalEthSpec>(&ChainSpec::minimal())
        .expect("apply config")
}

fn load_metadata() -> Metadata {
    let data =
        std::fs::read_to_string(vectors().join("metadata.json")).expect("read metadata.json");
    serde_json::from_str(&data).expect("parse metadata.json")
}

fn load_genesis_state(spec: &ChainSpec) -> BeaconState<MinimalEthSpec> {
    let era0 = std::fs::read_dir(era_path())
        .expect("read era dir")
        .filter_map(|e| e.ok())
        .find(|e| e.file_name().to_string_lossy().contains("-00000-"))
        .expect("ERA 0 file must exist");
    let file = std::fs::File::open(era0.path()).expect("open ERA 0");
    let era = reth_era::era::file::EraReader::new(file)
        .read_and_assemble("minimal".to_string())
        .expect("parse ERA 0");
    let bytes = era.group.era_state.decompress().expect("decompress ERA 0");
    BeaconState::from_ssz_bytes(&bytes, spec).expect("decode genesis state")
}

fn reference_state_root(spec: &ChainSpec) -> Hash256 {
    let last = std::fs::read_dir(era_path())
        .expect("readdir")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".era"))
        .max_by_key(|e| e.file_name().to_string_lossy().to_string())
        .expect("reference ERA file");
    let file = std::fs::File::open(last.path()).expect("open");
    let era = reth_era::era::file::EraReader::new(file)
        .read_and_assemble("minimal".to_string())
        .expect("parse");
    let bytes = era.group.era_state.decompress().expect("decompress");
    let mut state: BeaconState<MinimalEthSpec> =
        BeaconState::from_ssz_bytes(&bytes, spec).expect("decode");
    state.canonical_root().expect("root")
}

type TestStore = HotColdDB<
    MinimalEthSpec,
    store::MemoryStore<MinimalEthSpec>,
    store::MemoryStore<MinimalEthSpec>,
>;

/// Open ERA dir, init genesis, import all ERAs, return store.
fn import_eras(trust: EraImportTrust) -> (Arc<TestStore>, ChainSpec) {
    let spec = load_spec();
    let mut genesis = load_genesis_state(&spec);
    let gvr = genesis.genesis_validators_root();

    let store = Arc::new(
        HotColdDB::open_ephemeral(StoreConfig::default(), Arc::new(spec.clone())).expect("store"),
    );

    // Genesis init — sets up split, anchor, fork choice at genesis
    init_genesis_store(&store, &mut genesis, &spec).expect("init genesis");

    let era_dir =
        EraFileDir::new::<MinimalEthSpec>(&era_path(), gvr, trust, &spec).expect("open ERA dir");
    era_dir.import_all(&store, &spec).expect("import");

    (store, spec)
}

/// Store with genesis only (for individual import_era_file tests).
fn store_with_genesis(spec: &ChainSpec) -> TestStore {
    let store =
        HotColdDB::open_ephemeral(StoreConfig::default(), Arc::new(spec.clone())).expect("store");
    let mut genesis = load_genesis_state(spec);
    let root = genesis.canonical_root().expect("hash");
    let mut ops = vec![];
    store
        .store_cold_state(&root, &genesis, &mut ops)
        .expect("ops");
    store.cold_db.do_atomically(ops).expect("write");
    store
}

/// Copy ERA dir with one file replaced by a corrupt version.
fn era_dir_with_corrupt(corrupt_file: &str, target_pattern: &str) -> tempfile::TempDir {
    let tmp = tempfile::TempDir::new().expect("tmp");
    let dst = tmp.path().join("era");
    std::fs::create_dir_all(&dst).expect("mkdir");

    for entry in std::fs::read_dir(era_path()).expect("readdir") {
        let entry = entry.expect("entry");
        let name = entry.file_name().to_string_lossy().to_string();
        let src = if name.contains(target_pattern) {
            vectors().join("corrupt").join(corrupt_file)
        } else {
            entry.path()
        };
        std::fs::copy(src, dst.join(&name)).expect("copy");
    }
    tmp
}

/// Import ERAs up to target_era with one corrupt file, assert failure message.
fn assert_import_fails(corrupt_file: &str, target_pattern: &str, target_era: u64, expected: &str) {
    let tmp = era_dir_with_corrupt(corrupt_file, target_pattern);
    let spec = load_spec();
    let gvr = load_genesis_state(&spec).genesis_validators_root();
    let era_dir = EraFileDir::new::<MinimalEthSpec>(
        &tmp.path().join("era"),
        gvr,
        EraImportTrust::Untrusted,
        &spec,
    )
    .expect("init should succeed");
    let store = store_with_genesis(&spec);

    for era in 0..target_era {
        era_dir
            .import_era_file(&store, era, &spec)
            .unwrap_or_else(|e| panic!("ERA {era}: {e}"));
    }

    let err = era_dir
        .import_era_file(&store, target_era, &spec)
        .unwrap_err();
    assert!(
        err.contains(expected),
        "expected \"{expected}\", got: {err}"
    );
}

/// Assert that EraFileDir::new fails with a corrupt file.
fn assert_init_fails(corrupt_file: &str, target_pattern: &str, expected: &str) {
    let tmp = era_dir_with_corrupt(corrupt_file, target_pattern);
    let spec = load_spec();
    let gvr = load_genesis_state(&spec).genesis_validators_root();
    let err = EraFileDir::new::<MinimalEthSpec>(
        &tmp.path().join("era"),
        gvr,
        EraImportTrust::Untrusted,
        &spec,
    )
    .unwrap_err();
    assert!(
        err.contains(expected),
        "expected \"{expected}\", got: {err}"
    );
}

// Single #[test] to avoid nextest parallel download races.
// See slashing_protection/tests/interop.rs for the same pattern.
#[test]
fn era_test_vectors() {
    consumer_imports_and_verifies();
    consumer_imports_with_trusted_state_root();
    producer_output_is_byte_identical();
    rejects_corrupted_block_decompression();
    rejects_corrupted_genesis_state();
    rejects_corrupted_middle_state();
    rejects_corrupted_reference_state();
    rejects_wrong_era_content();
    rejects_wrong_era_root();
    rejects_corrupt_block_summary();
    rejects_wrong_block_root();
    rejects_mutated_reference_state_with_trusted_root();
    rejects_wrong_trusted_state_root();
    producer_skips_boundary_block_from_previous_era();
}

fn consumer_imports_and_verifies() {
    let metadata = load_metadata();
    let (store, spec) = import_eras(EraImportTrust::Untrusted);
    let slots_per_era = MinimalEthSpec::slots_per_historical_root() as u64;

    assert_eq!(MAX_ERA + 1, metadata.era_count, "era count mismatch");

    let head_key = metadata.head_slot.to_be_bytes().to_vec();
    let head_root_bytes = store
        .cold_db
        .get_bytes(DBColumn::BeaconBlockRoots, &head_key)
        .expect("read")
        .expect("head root exists");
    let head_root = Hash256::from_slice(&head_root_bytes);
    let expected = Hash256::from_slice(&hex::decode(&metadata.head_root).expect("hex"));
    assert_eq!(head_root, expected, "head root mismatch");

    let head_block = store
        .get_full_block(&head_root)
        .expect("query")
        .expect("head block exists");
    assert_eq!(head_block.canonical_root(), head_root);
    assert_eq!(
        head_block.slot(),
        Slot::new(metadata.head_slot),
        "last indexed slot is {}",
        MAX_ERA * slots_per_era - 1
    );

    chain_boots_from_imported_db(store, &spec, &metadata);
}

fn consumer_imports_with_trusted_state_root() {
    let metadata = load_metadata();
    let spec = load_spec();
    let root = reference_state_root(&spec);
    let (store, spec) = import_eras(EraImportTrust::TrustedStateRoot(MAX_ERA, root));

    let head_key = metadata.head_slot.to_be_bytes().to_vec();
    let head_root_bytes = store
        .cold_db
        .get_bytes(DBColumn::BeaconBlockRoots, &head_key)
        .expect("read")
        .expect("head root exists");
    let expected = hex::decode(&metadata.head_root).expect("hex");
    assert_eq!(head_root_bytes, expected);

    chain_boots_from_imported_db(store, &spec, &metadata);
}

fn producer_output_is_byte_identical() {
    let (store, _spec) = import_eras(EraImportTrust::Untrusted);
    let output = PathBuf::from("/tmp/era_producer_test_output");
    let _ = std::fs::remove_dir_all(&output);
    std::fs::create_dir_all(&output).expect("mkdir");

    for era in 0..=MAX_ERA {
        super::producer::create_era_file(&store, era, &output)
            .unwrap_or_else(|e| panic!("produce ERA {era}: {e}"));
    }

    let list_era = |dir: PathBuf| -> Vec<_> {
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .expect("readdir")
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".era"))
            .collect();
        files.sort_by_key(|e| e.file_name());
        files
    };

    let originals = list_era(era_path());
    let produced = list_era(output);
    assert_eq!(originals.len(), produced.len(), "file count mismatch");

    for (orig, prod) in originals.iter().zip(produced.iter()) {
        assert_eq!(
            std::fs::read(orig.path()).expect("read"),
            std::fs::read(prod.path()).expect("read"),
            "ERA mismatch: {:?}",
            orig.file_name()
        );
    }
}

fn rejects_corrupted_block_decompression() {
    assert_import_fails("era1-corrupt-block.era", "-00001-", 1, "decompress");
}

fn rejects_corrupted_genesis_state() {
    assert_import_fails("era0-corrupt-state.era", "-00000-", 0, "decompress");
}

fn rejects_corrupted_middle_state() {
    assert_import_fails("era5-corrupt-state.era", "-00005-", 5, "decompress");
}

fn rejects_corrupted_reference_state() {
    assert_init_fails("era12-corrupt-state.era", "-00012-", "decompress");
}

fn rejects_wrong_era_content() {
    assert_import_fails(
        "era3-wrong-content.era",
        "-00003-",
        3,
        "era state slot mismatch",
    );
}

fn rejects_wrong_era_root() {
    assert_import_fails("era0-wrong-root.era", "-00000-", 0, "era root mismatch");
}

fn rejects_corrupt_block_summary() {
    assert_import_fails(
        "era8-corrupt-block-summary.era",
        "-00008-",
        8,
        "block summary root post-capella mismatch",
    );
}

fn rejects_wrong_block_root() {
    assert_import_fails(
        "era2-wrong-block-root.era",
        "-00002-",
        2,
        "block root mismatch",
    );
}

fn rejects_mutated_reference_state_with_trusted_root() {
    let tmp = era_dir_with_corrupt("era12-corrupt-state.era", "-00012-");
    let spec = load_spec();
    let gvr = load_genesis_state(&spec).genesis_validators_root();
    let root = reference_state_root(&spec);
    let err = EraFileDir::new::<MinimalEthSpec>(
        &tmp.path().join("era"),
        gvr,
        EraImportTrust::TrustedStateRoot(MAX_ERA, root),
        &spec,
    )
    .unwrap_err();
    assert!(err.contains("decompress"), "expected decompress: {err}");
}

fn rejects_wrong_trusted_state_root() {
    let spec = load_spec();
    let gvr = load_genesis_state(&spec).genesis_validators_root();
    let correct = reference_state_root(&spec);

    // Correct root succeeds
    EraFileDir::new::<MinimalEthSpec>(
        &era_path(),
        gvr,
        EraImportTrust::TrustedStateRoot(MAX_ERA, correct),
        &spec,
    )
    .expect("correct root should pass");

    // Wrong root fails
    let mut bytes: [u8; 32] = correct.into();
    bytes[0] ^= 0x01;
    let err = EraFileDir::new::<MinimalEthSpec>(
        &era_path(),
        gvr,
        EraImportTrust::TrustedStateRoot(MAX_ERA, Hash256::from(bytes)),
        &spec,
    )
    .unwrap_err();
    assert!(
        err.contains("trusted state root mismatch"),
        "expected trusted state root mismatch: {err}"
    );
}

/// Verify that a BeaconChain can boot from an ERA-imported store.
///
/// This function MUST NOT write any new data to the store. It boots a BeaconChain using the
/// regular `resume_from_db` path (same as `lighthouse bn` restart) and verifies:
/// - `canonical_head` equals the expected head root from metadata
/// - For every slot in 0..head_slot:
///   - state_root_at_slot + get_state succeeds and returned state.slot() matches
///     (same code path as HTTP API `GET /eth/v2/debug/beacon/states/{slot}`)
///   - block_root_at_slot + get_blinded_block succeeds for non-skipped slots and
///     returned block.slot() matches
///     (same code path as HTTP API `GET /eth/v2/beacon/blocks/{slot}`)
fn chain_boots_from_imported_db(store: Arc<TestStore>, spec: &ChainSpec, metadata: &Metadata) {
    let expected_head_root =
        Hash256::from_slice(&hex::decode(&metadata.head_root).expect("decode head root hex"));

    // Boot via resume_from_db — the same path lighthouse bn uses on restart.
    // The slot clock must be at or beyond the head slot, as the real beacon node would be.
    // The ERA boundary slot is one past the head block slot (the split point).
    let era_boundary_slot =
        (metadata.head_slot / MinimalEthSpec::slots_per_historical_root() as u64 + 1)
            * MinimalEthSpec::slots_per_historical_root() as u64;
    let genesis_time = Duration::from_secs(spec.min_genesis_time);
    let slot_duration = Duration::from_secs(spec.seconds_per_slot);
    let clock_time = genesis_time + slot_duration * era_boundary_slot as u32;
    let slot_clock = TestingSlotClock::new(Slot::new(0), genesis_time, slot_duration);
    slot_clock.set_current_time(clock_time);

    let harness = BeaconChainHarness::builder(MinimalEthSpec)
        .spec(Arc::new(spec.clone()))
        .deterministic_keypairs(1)
        .testing_slot_clock(slot_clock)
        .resumed_ephemeral_store(store)
        .build();

    // canonical_head matches expected value
    let head = harness.chain.head();
    assert_eq!(
        head.head_block_root(),
        expected_head_root,
        "canonical head root mismatch"
    );

    // Every slot's state and block are accessible through the chain (HTTP API code path).
    let head_slot = metadata.head_slot;
    let mut block_count = 0u64;
    let mut prev_block_root = None;
    for slot_u64 in 0..head_slot {
        let slot = Slot::new(slot_u64);

        // State by slot: chain.state_root_at_slot → chain.get_state
        let state_root = harness
            .chain
            .state_root_at_slot(slot)
            .unwrap_or_else(|e| panic!("state_root_at_slot({slot}) failed: {e:?}"))
            .unwrap_or_else(|| panic!("no state root at slot {slot}"));
        let state = harness
            .chain
            .get_state(&state_root, Some(slot), false)
            .unwrap_or_else(|e| panic!("get_state at slot {slot} failed: {e:?}"))
            .unwrap_or_else(|| panic!("state not found at slot {slot}"));
        assert_eq!(state.slot(), slot, "state slot mismatch at slot {slot}");

        // Block by slot: chain.block_root_at_slot → chain.get_blinded_block
        // WhenSlotSkipped::None mirrors the HTTP API (returns None for skip slots).
        if let Some(block_root) = harness
            .chain
            .block_root_at_slot(slot, WhenSlotSkipped::None)
            .unwrap_or_else(|e| panic!("block_root_at_slot({slot}) failed: {e:?}"))
        {
            let block = harness
                .chain
                .get_blinded_block(&block_root)
                .unwrap_or_else(|e| panic!("get_blinded_block at slot {slot} failed: {e:?}"))
                .unwrap_or_else(|| panic!("block not found at slot {slot}"));
            assert_eq!(block.slot(), slot, "block slot mismatch at slot {slot}");

            // Verify parent chain: each block's parent_root must equal the previous block's root.
            if let Some(prev_root) = prev_block_root {
                assert_eq!(
                    block.parent_root(),
                    prev_root,
                    "parent_root mismatch at slot {slot}"
                );
            }
            prev_block_root = Some(block_root);
            block_count += 1;
        }
    }
    // Sanity check: the testnet has 767 blocks (metadata), so we must have found them all.
    // This guards against a silent pass when block_root_at_slot returns None for every slot.
    assert!(
        block_count > head_slot / 2,
        "too few blocks found: {block_count} out of {head_slot} slots"
    );
}

/// Regression test: when the first slot of an ERA's block range is missed, the producer must
/// NOT include the block from the previous ERA.
///
/// Background: `state.get_block_root(slot)` returns the most recent block root at or before
/// `slot`. For a missed boundary slot, this is the last block of the prior ERA. The producer
/// must detect this duplicate and skip it by checking `block.slot() >= start_slot`.
///
/// This test synthetically creates a missed boundary slot by:
/// 1. Loading the state from the previous ERA to get the root of the last block before the boundary
/// 2. Modifying the target ERA's state so the boundary slot's block_root points to that old block
/// 3. Verifying `build_era_group` does not include the out-of-range block
fn producer_skips_boundary_block_from_previous_era() {
    let (store, spec) = import_eras(EraImportTrust::Untrusted);
    let slots_per_era = MinimalEthSpec::slots_per_historical_root() as u64;

    // Use ERA 5 (block range: slots 256..320, state at slot 320).
    // We'll make slot 256 a "miss" by pointing its block_root to a block from ERA 4.
    let target_era: u64 = 5;
    let start_slot = Slot::new((target_era - 1) * slots_per_era); // slot 256
    let end_slot = Slot::new(target_era * slots_per_era); // slot 320

    // Load the state at ERA 4's end slot (slot 256) to get the root of the last block
    // before the ERA 5 boundary. The previous ERA's state covers slots 192..255.
    let prev_era_end = Slot::new((target_era - 1) * slots_per_era); // slot 256
    let prev_state = store
        .load_cold_state_by_slot(prev_era_end)
        .expect("load prev ERA state");
    // Slot 255 is the last slot in ERA 4's block range
    let last_prev_slot = Slot::new(start_slot.as_u64() - 1); // slot 255
    let prev_block_root = *prev_state
        .get_block_root(last_prev_slot)
        .expect("get root for last slot of previous ERA");

    // Verify the block at that root actually has slot < start_slot
    let prev_block = store
        .get_blinded_block(&prev_block_root)
        .expect("query")
        .expect("block exists");
    assert!(
        prev_block.slot() < start_slot,
        "precondition: block at root should have slot < {start_slot}, got {}",
        prev_block.slot()
    );

    // Load the state at ERA 5's end slot
    let mut state = store
        .load_cold_state_by_slot(end_slot)
        .expect("load state at end_slot");
    assert_eq!(state.slot(), end_slot);

    // Count blocks before modification (baseline)
    let baseline = super::producer::build_era_group::<MinimalEthSpec, _, _>(
        &store,
        &mut state.clone(),
        target_era,
    )
    .expect("baseline build_era_group");
    let baseline_count = baseline.blocks.len();

    // Simulate missed boundary slot: set block_root for slot 256 to the root of
    // a block from ERA 4. This mimics what happens when no block is proposed at slot 256.
    state
        .set_block_root(start_slot, prev_block_root)
        .expect("set block root");

    // Now build the ERA group with the modified state
    let group =
        super::producer::build_era_group::<MinimalEthSpec, _, _>(&store, &mut state, target_era)
            .expect("build_era_group with missed boundary");

    // The modified ERA should have one fewer block (the boundary slot is now "missed")
    assert_eq!(
        group.blocks.len(),
        baseline_count - 1,
        "missed boundary slot should produce one fewer block"
    );

    // Verify no block in the produced group has a slot before the boundary
    for block in &group.blocks {
        let bytes = block.decompress().expect("decompress block");
        let decoded =
            SignedBeaconBlock::<MinimalEthSpec>::from_ssz_bytes(&bytes, &spec).expect("decode");
        assert!(
            decoded.slot() >= start_slot,
            "block at slot {} is before ERA start slot {} — boundary block leak",
            decoded.slot(),
            start_slot,
        );
    }
}
