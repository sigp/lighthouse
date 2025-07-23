use beacon_chain::{
    ChainConfig,
    persisted_beacon_chain::PersistedBeaconChain,
    persisted_custody::PersistedCustody,
    test_utils::{BeaconChainHarness, DiskHarnessType, test_spec},
};
use logging::create_test_tracing_subscriber;
use operation_pool::PersistedOperationPool;
use ssz::Encode;
use std::sync::{Arc, LazyLock};
use store::{
    DBColumn, HotColdDB, StoreConfig, StoreItem,
    database::interface::BeaconNodeBackend,
    hot_cold_store::Split,
    metadata::{DataColumnCustodyInfo, DataColumnInfo},
};
use strum::IntoEnumIterator;
use tempfile::{TempDir, tempdir};
use types::{ChainSpec, Hash256, Keypair, MainnetEthSpec, Slot};

type E = MainnetEthSpec;
type Store<E> = Arc<HotColdDB<E, BeaconNodeBackend<E>, BeaconNodeBackend<E>>>;
type TestHarness = BeaconChainHarness<DiskHarnessType<E>>;

const VALIDATOR_COUNT: usize = 32;

/// A cached set of keys.
static KEYPAIRS: LazyLock<Vec<Keypair>> =
    LazyLock::new(|| types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT));

fn get_store(db_path: &TempDir, config: StoreConfig, spec: Arc<ChainSpec>) -> Store<E> {
    create_test_tracing_subscriber();
    let hot_path = db_path.path().join("chain_db");
    let cold_path = db_path.path().join("freezer_db");
    let blobs_path = db_path.path().join("blobs_db");

    HotColdDB::open(
        &hot_path,
        &cold_path,
        &blobs_path,
        |_, _, _| Ok(()),
        config,
        spec,
    )
    .expect("disk store should initialize")
}

/// This test checks the database schema stability against previous versions of Lighthouse's code.
///
/// If you are changing something about how Lighthouse stores data on disk, you almost certainly
/// need to implement a database schema change. This is true even if the data being stored only
/// applies to an upcoming fork that isn't live on mainnet. We never want to be in the situation
/// where commit A writes data in some format, and then a later commit B changes that format
/// without a schema change. This is liable to break any nodes that update from A to B, even if
/// these nodes are just testnet nodes.
///
/// This test implements partial, imperfect checks on the DB schema which are designed to quickly
/// catch common changes.
///
/// This test uses hardcoded values, rather than trying to access previous versions of Lighthouse's
/// code. If you've successfully implemented a schema change and you're sure that the new values are
/// correct, you can update the hardcoded values here.
#[tokio::test]
async fn schema_stability() {
    let spec = Arc::new(test_spec::<E>());

    let datadir = tempdir().unwrap();
    let store_config = StoreConfig::default();
    let store = get_store(&datadir, store_config, spec.clone());

    let chain_config = ChainConfig {
        reconstruct_historic_states: true,
        ..ChainConfig::default()
    };

    let harness = TestHarness::builder(MainnetEthSpec)
        .spec(spec)
        .keypairs(KEYPAIRS.to_vec())
        .fresh_disk_store(store.clone())
        .mock_execution_layer()
        .chain_config(chain_config)
        .build();
    harness.advance_slot();

    let chain = &harness.chain;

    chain.persist_op_pool().unwrap();
    chain.persist_custody_context().unwrap();
    insert_data_column_custody_info(&store, &harness.spec);

    check_db_columns();
    check_metadata_sizes(&store);
    check_op_pool(&store);
    check_custody_context(&store, &harness.spec);
    check_custody_info(&store, &harness.spec);
    check_persisted_chain(&store);

    // Not covered here:
    // - Fork choice (not tested)
    // - DBColumn::DhtEnrs (tested in network crate)
}

/// Check that the set of database columns is unchanged.
fn check_db_columns() {
    let current_columns: Vec<&'static str> = DBColumn::iter().map(|c| c.as_str()).collect();
    let expected_columns = vec![
        "bma", "blk", "blb", "bdc", "bdi", "ste", "hsd", "hsn", "bsn", "bsd", "bss", "bs3", "bcs",
        "bst", "exp", "bch", "opo", "etc", "frk", "pkc", "brp", "bsx", "bsr", "bbx", "bbr", "bhr",
        "brm", "dht", "cus", "otb", "bhs", "olc", "lcu", "scb", "scm", "dmy",
    ];
    assert_eq!(expected_columns, current_columns);
}

fn insert_data_column_custody_info(store: &Store<E>, spec: &ChainSpec) {
    if spec.is_peer_das_scheduled() {
        store
            .put_data_column_custody_info(Some(Slot::new(0)))
            .unwrap();
    }
}

/// Check the SSZ sizes of known on-disk metadata.
///
/// New types can be added here as the schema evolves.
fn check_metadata_sizes(store: &Store<E>) {
    assert_eq!(Split::default().ssz_bytes_len(), 40);
    assert_eq!(store.get_anchor_info().ssz_bytes_len(), 64);
    assert_eq!(
        store.get_blob_info().ssz_bytes_len(),
        if store.get_chain_spec().deneb_fork_epoch.is_some() {
            14
        } else {
            6
        }
    );
    assert_eq!(DataColumnInfo::default().ssz_bytes_len(), 5);
    assert_eq!(DataColumnCustodyInfo::default().ssz_bytes_len(), 5);
}

fn check_op_pool(store: &Store<E>) {
    let op_pool = store
        .get_item::<PersistedOperationPool<E>>(&Hash256::ZERO)
        .unwrap()
        .unwrap();
    assert!(matches!(op_pool, PersistedOperationPool::V20(_)));
    assert_eq!(op_pool.ssz_bytes_len(), 28);
    assert_eq!(op_pool.as_store_bytes().len(), 28);
}

fn check_custody_context(store: &Store<E>, spec: &ChainSpec) {
    let custody_context_opt = store.get_item::<PersistedCustody>(&Hash256::ZERO).unwrap();
    if spec.is_peer_das_scheduled() {
        assert_eq!(custody_context_opt.unwrap().as_store_bytes().len(), 13);
    } else {
        assert!(custody_context_opt.is_none());
    }
}

fn check_custody_info(store: &Store<E>, spec: &ChainSpec) {
    let data_column_custody_info = store.get_data_column_custody_info().unwrap();
    if spec.is_peer_das_scheduled() {
        assert_eq!(data_column_custody_info.unwrap().as_ssz_bytes().len(), 13);
    } else {
        assert!(data_column_custody_info.is_none());
    }
}

fn check_persisted_chain(store: &Store<E>) {
    let chain = store
        .get_item::<PersistedBeaconChain>(&Hash256::ZERO)
        .unwrap()
        .unwrap();
    assert_eq!(chain.as_store_bytes().len(), 32);
}
