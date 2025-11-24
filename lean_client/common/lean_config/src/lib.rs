mod validators;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use lean_consensus::lean_state::LeanState;
use lean_genesis::ValidatorConfig;
use lean_keystore::{DEFAULT_KEYS_DIR, KeyStore, ValidatorKeyPair};
use lean_network::NetworkConfig;
use lean_network_config::load_network_files;
use lean_store::LeanStore;
use slot_clock::{SlotClock, SystemTimeSlotClock};
use store::database::interface::BeaconNodeBackend;
use tracing::info;
use types::{EthSpec, Slot, milhouse};

use validators::{build_validators, current_unix_timestamp};

/// Input paths and identifiers required to build the lean client runtime.
pub struct LeanClientPaths {
    pub data_dir: PathBuf,
    pub config_path: PathBuf,
    pub validators_path: PathBuf,
    pub nodes_path: PathBuf,
    pub node_id: String,
}

/// Runtime resources required by the lean client services.
pub struct LeanClientResources<E: EthSpec> {
    pub slot_clock: SystemTimeSlotClock,
    pub db: Arc<BeaconNodeBackend<E>>,
    pub validator_key_pair: ValidatorKeyPair,
    pub keystore: KeyStore,
    pub network_config: NetworkConfig,
}

/// Load all configuration and runtime data needed to run the lean client.
pub fn initialize<E: EthSpec>(paths: LeanClientPaths) -> Result<LeanClientResources<E>, String> {
    let LeanClientPaths {
        data_dir,
        config_path,
        validators_path,
        nodes_path,
        node_id,
    } = paths;

    std::fs::create_dir_all(&data_dir)
        .map_err(|e| format!("Failed to create data directory {:?}: {}", data_dir, e))?;

    let db_path = data_dir.join("lean_db");
    let store_config = store::StoreConfig::default();
    let db = Arc::new(
        BeaconNodeBackend::open(&store_config, &db_path)
            .map_err(|e| format!("Failed to open database: {:?}", e))?,
    );
    let lean_store = LeanStore::new(db.clone());

    let validator_config = ValidatorConfig::load_from_file(&validators_path).map_err(|e| {
        format!(
            "Failed to load validator config from {:?}: {}",
            validators_path, e
        )
    })?;

    let validators_dir = validators_path
        .parent()
        .ok_or_else(|| "validators.yaml path has no parent directory".to_string())?;
    let keystore_dir = validators_dir.join(DEFAULT_KEYS_DIR);
    let keystore = KeyStore::new(keystore_dir.clone());

    let all_key_pairs = keystore
        .load_all_key_pairs()
        .map_err(|e| format!("Failed to load validators from keystore: {}", e))?;

    info!(
        total_validators = all_key_pairs.len(),
        "Loaded validators from keystore"
    );

    if all_key_pairs.is_empty() {
        return Err(
            "No validators found in keystore. Please generate validators first.".to_string(),
        );
    }

    let validators_list = build_validators(all_key_pairs)?;
    let validators = milhouse::List::new(validators_list)
        .map_err(|e| format!("Failed to create List from validators: {:?}", e))?;
    let mut genesis_state = LeanState::<E>::genesis_default().generate_genesis(validators);

    let current_time = current_unix_timestamp()?;
    genesis_state.config.genesis_time = current_time;

    info!(
        slot = genesis_state.slot.0,
        genesis_time = genesis_state.config.genesis_time,
        validators_count = genesis_state.validators.len(),
        "Initialized genesis state with validators"
    );

    lean_store
        .save_state(&genesis_state)
        .map_err(|e| format!("Failed to save genesis state to database: {}", e))?;
    info!("Saved genesis state to database");

    let slot_clock = SystemTimeSlotClock::new(
        Slot::new(0),
        Duration::from_secs(genesis_state.config.genesis_time),
        Duration::from_secs(genesis_state.config.seconds_per_slot),
    );

    let validator_assignments = validator_config.validator_assignments();
    let (start_index, _end_index) = validator_assignments
        .get(&node_id)
        .ok_or_else(|| format!("Node ID '{}' not found in validator config", node_id))?;

    info!(
        node_id = node_id,
        validator_start_index = start_index,
        validator_count = validator_config
            .validators
            .iter()
            .find(|v| v.name == node_id)
            .map(|v| v.count)
            .unwrap_or(0),
        "Found validator assignment for node"
    );

    let validator_key_pair = keystore.load_key_pair(*start_index).map_err(|e| {
        format!(
            "Failed to load keystore for validator index {}: {}",
            start_index, e
        )
    })?;

    info!(
        validator_index = start_index,
        keystore_dir = ?keystore_dir,
        "Loaded XMSS key pair from keystore"
    );

    let config_info = load_network_files(&config_path, &nodes_path)
        .map_err(|e| format!("Failed to load network config: {}", e))?;

    let listen_port = validator_config
        .validators
        .iter()
        .find(|v| v.name == node_id)
        .and_then(|v| v.enr_fields.as_ref())
        .and_then(|e| e.quic)
        .unwrap_or(9000);

    info!(
        config = ?config_path,
        validators = ?validators_path,
        nodes = ?nodes_path,
        listen_port,
        node_id,
        bootstrap_nodes = config_info.bootstrap_enrs.len(),
        "Lean node configuration loaded"
    );

    let network_config =
        NetworkConfig::new(listen_port).with_bootstrap_nodes(config_info.bootstrap_enrs);

    Ok(LeanClientResources {
        slot_clock,
        db,
        validator_key_pair,
        keystore,
        network_config,
    })
}
