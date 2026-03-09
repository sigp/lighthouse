/// ERA file consumer + producer tests using minimal preset test vectors.
///
/// Test vectors: 13 ERA files from a Nimbus minimal testnet.
/// - Electra from genesis, Fulu at epoch 100000
/// - SLOTS_PER_HISTORICAL_ROOT = 64 (one ERA = 64 slots = 8 epochs)
/// - 13 ERA files covering 832 slots, 767 blocks, 1024 validators
///
/// All subtests run from a single #[test] to avoid nextest download races
/// (same pattern as slashing_protection/tests/interop.rs).
use super::consumer::EraFileDir;
use reth_era::common::file_ops::StreamReader;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};
use store::{DBColumn, HotColdDB, KeyValueStore, StoreConfig};
use types::{BeaconState, ChainSpec, Config, EthSpec, Hash256, MinimalEthSpec, Slot};

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

fn test_vectors_dir() -> &'static PathBuf {
    &TEST_VECTORS_DIR
}

fn load_test_spec() -> ChainSpec {
    let config_str =
        std::fs::read_to_string(test_vectors_dir().join("config.yaml")).expect("read config.yaml");
    let config: Config = serde_yaml::from_str(&config_str).expect("parse config");
    config
        .apply_to_chain_spec::<MinimalEthSpec>(&ChainSpec::minimal())
        .expect("apply config")
}

fn load_genesis_state(spec: &ChainSpec) -> BeaconState<MinimalEthSpec> {
    let era_dir = test_vectors_dir().join("era");
    let era0_path = std::fs::read_dir(&era_dir)
        .expect("read era dir")
        .filter_map(|e| e.ok())
        .find(|e| e.file_name().to_string_lossy().contains("-00000-"))
        .expect("ERA 0 file must exist");
    let file = std::fs::File::open(era0_path.path()).expect("open ERA 0");
    let era = reth_era::era::file::EraReader::new(file)
        .read_and_assemble("minimal".to_string())
        .expect("parse ERA 0");
    let state_bytes = era
        .group
        .era_state
        .decompress()
        .expect("decompress ERA 0 state");
    BeaconState::from_ssz_bytes(&state_bytes, spec).expect("decode genesis state from ERA 0")
}

type TestStore = HotColdDB<
    MinimalEthSpec,
    store::MemoryStore<MinimalEthSpec>,
    store::MemoryStore<MinimalEthSpec>,
>;

fn import_all_era_files() -> (TestStore, ChainSpec, u64) {
    let spec = load_test_spec();
    let era_dir_path = test_vectors_dir().join("era");
    let era_dir = EraFileDir::new::<MinimalEthSpec>(&era_dir_path, &spec).expect("open ERA dir");
    let max_era = era_dir.max_era();

    let store = HotColdDB::open_ephemeral(StoreConfig::default(), Arc::new(spec.clone()))
        .expect("create store");

    let mut genesis_state = load_genesis_state(&spec);
    era_dir
        .import_all(&store, &mut genesis_state, &spec)
        .expect("import all ERA files");

    (store, spec, max_era)
}

fn empty_store(spec: &ChainSpec) -> TestStore {
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

fn era_dir_with_corrupt(corrupt_file: &str, target_pattern: &str) -> tempfile::TempDir {
    let tmp = tempfile::TempDir::new().expect("tmp");
    let src = test_vectors_dir();
    let dst = tmp.path().join("era");
    std::fs::create_dir_all(&dst).expect("mkdir");

    for entry in std::fs::read_dir(src.join("era")).expect("readdir") {
        let entry = entry.expect("entry");
        let name = entry.file_name().to_string_lossy().to_string();
        if name.contains(target_pattern) {
            std::fs::copy(src.join("corrupt").join(corrupt_file), dst.join(&name))
                .expect("copy corrupt");
        } else {
            std::fs::copy(entry.path(), dst.join(&name)).expect("copy");
        }
    }
    tmp
}

fn assert_import_fails(
    corrupt_file: &str,
    target_pattern: &str,
    target_era: u64,
    expected_err: &str,
) {
    let tmp = era_dir_with_corrupt(corrupt_file, target_pattern);
    let spec = load_test_spec();
    let era_dir = EraFileDir::new::<MinimalEthSpec>(&tmp.path().join("era"), &spec)
        .expect("init should succeed");
    let store = empty_store(&spec);

    for era in 0..target_era {
        era_dir
            .import_era_file(&store, era, &spec, None)
            .unwrap_or_else(|e| panic!("ERA {era}: {e}"));
    }

    let err = era_dir
        .import_era_file(&store, target_era, &spec, None)
        .unwrap_err();
    assert!(
        err.contains(expected_err),
        "expected \"{expected_err}\", got: {err}"
    );
}

fn era3_correct_root_and_slot(spec: &ChainSpec) -> (Hash256, types::Slot) {
    let era3_file = std::fs::read_dir(test_vectors_dir().join("era"))
        .expect("readdir")
        .filter_map(|e| e.ok())
        .find(|e| e.file_name().to_string_lossy().contains("-00003-"))
        .expect("ERA 3");
    let file = std::fs::File::open(era3_file.path()).expect("open");
    let era = reth_era::era::file::EraReader::new(file)
        .read_and_assemble("minimal".to_string())
        .expect("parse");
    let state_bytes = era.group.era_state.decompress().expect("decompress");
    let mut state: BeaconState<MinimalEthSpec> =
        BeaconState::from_ssz_bytes(&state_bytes, spec).expect("decode");
    let root = state.canonical_root().expect("root");
    let slot = state.slot();
    (root, slot)
}

// Single #[test] to avoid nextest parallel download races.
// See slashing_protection/tests/interop.rs for the same pattern.
#[test]
fn era_test_vectors() {
    consumer_imports_and_verifies();
    producer_output_is_byte_identical();
    rejects_corrupted_block_decompression();
    rejects_corrupted_genesis_state();
    rejects_corrupted_middle_state();
    rejects_corrupted_reference_state();
    rejects_wrong_era_content();
    rejects_wrong_era_root();
    rejects_corrupt_block_summary();
    rejects_wrong_block_root();
    rejects_mutated_state_with_trusted_root();
    rejects_wrong_trusted_state_root();
}

fn load_metadata() -> Metadata {
    let path = test_vectors_dir().join("metadata.json");
    let data = std::fs::read_to_string(&path).expect("read metadata.json");
    serde_json::from_str(&data).expect("parse metadata.json")
}

fn consumer_imports_and_verifies() {
    let metadata = load_metadata();
    let (store, _spec, max_era) = import_all_era_files();
    let slots_per_era = MinimalEthSpec::slots_per_historical_root() as u64;

    assert_eq!(max_era + 1, metadata.era_count, "era count mismatch");

    // The last indexed slot is (max_era * slots_per_era - 1), since the ERA boundary
    // state covers [start_slot, end_slot) where end_slot = era_number * slots_per_era.
    let last_slot = max_era * slots_per_era - 1;

    // Verify head block root matches metadata
    let head_key = metadata.head_slot.to_be_bytes().to_vec();
    let head_root_bytes = store
        .cold_db
        .get_bytes(DBColumn::BeaconBlockRoots, &head_key)
        .expect("read head root index")
        .unwrap_or_else(|| panic!("no block root at head slot {}", metadata.head_slot));
    let head_root = Hash256::from_slice(&head_root_bytes);

    let expected_head_root_bytes = hex::decode(&metadata.head_root).expect("decode head_root hex");
    let expected_head_root = Hash256::from_slice(&expected_head_root_bytes);
    assert_eq!(
        head_root, expected_head_root,
        "head root mismatch at slot {}: got {head_root:?}",
        metadata.head_slot
    );

    // Verify the head block exists and has the correct root
    let head_block = store
        .get_full_block(&head_root)
        .expect("query head block")
        .unwrap_or_else(|| panic!("head block missing at slot {}", metadata.head_slot));
    assert_eq!(head_block.canonical_root(), head_root);
    assert_eq!(
        head_block.slot(),
        Slot::new(metadata.head_slot),
        "last indexed slot is {last_slot}"
    );
}

fn producer_output_is_byte_identical() {
    let (store, _spec, max_era) = import_all_era_files();
    let output = PathBuf::from("/tmp/era_producer_test_output");
    let _ = std::fs::remove_dir_all(&output);
    std::fs::create_dir_all(&output).expect("mkdir");

    for era in 0..=max_era {
        super::producer::create_era_file(&store, era, &output)
            .unwrap_or_else(|e| panic!("produce ERA {era}: {e}"));
    }

    let mut originals: Vec<_> = std::fs::read_dir(test_vectors_dir().join("era"))
        .expect("readdir")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".era"))
        .collect();
    originals.sort_by_key(|e| e.file_name());

    let mut produced: Vec<_> = std::fs::read_dir(&output)
        .expect("readdir")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".era"))
        .collect();
    produced.sort_by_key(|e| e.file_name());

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
    let tmp = era_dir_with_corrupt("era12-corrupt-state.era", "-00012-");
    let spec = load_test_spec();
    match EraFileDir::new::<MinimalEthSpec>(&tmp.path().join("era"), &spec) {
        Ok(_) => panic!("should fail with corrupted reference state"),
        Err(err) => assert!(err.contains("decompress"), "expected decompress: {err}"),
    }
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

fn rejects_mutated_state_with_trusted_root() {
    let tmp = era_dir_with_corrupt("era3-wrong-state-root.era", "-00003-");
    let spec = load_test_spec();
    let era_dir = EraFileDir::new::<MinimalEthSpec>(&tmp.path().join("era"), &spec)
        .expect("init should succeed");
    let store = empty_store(&spec);

    for era in 0..3 {
        era_dir
            .import_era_file(&store, era, &spec, None)
            .unwrap_or_else(|e| panic!("ERA {era}: {e}"));
    }

    let (correct_root, slot) = era3_correct_root_and_slot(&spec);

    let err = era_dir
        .import_era_file(&store, 3, &spec, Some((correct_root, slot)))
        .unwrap_err();
    assert!(
        err.contains("trusted state root mismatch"),
        "expected trusted state root mismatch: {err}"
    );
}

fn rejects_wrong_trusted_state_root() {
    let spec = load_test_spec();
    let store = empty_store(&spec);
    let era_dir_path = test_vectors_dir().join("era");
    let era_dir = EraFileDir::new::<MinimalEthSpec>(&era_dir_path, &spec).expect("open");

    for era in 0..=2 {
        era_dir
            .import_era_file(&store, era, &spec, None)
            .unwrap_or_else(|e| panic!("ERA {era}: {e}"));
    }

    let (correct_root, slot) = era3_correct_root_and_slot(&spec);

    era_dir
        .import_era_file(&store, 3, &spec, Some((correct_root, slot)))
        .expect("correct root should pass");

    let wrong_root = {
        let mut bytes: [u8; 32] = correct_root.into();
        bytes[0] ^= 0x01;
        Hash256::from(bytes)
    };

    let store2 = empty_store(&spec);
    for era in 0..=2 {
        era_dir
            .import_era_file(&store2, era, &spec, None)
            .unwrap_or_else(|e| panic!("ERA {era}: {e}"));
    }

    let err = era_dir
        .import_era_file(&store2, 3, &spec, Some((wrong_root, slot)))
        .unwrap_err();
    assert!(
        err.contains("trusted state root mismatch"),
        "expected trusted state root mismatch: {err}"
    );
}
