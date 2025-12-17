mod validators;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use lean_consensus::lean_block::{LeanBlock, LeanBlockBody};
use lean_consensus::lean_state::{LeanState, SECONDS_PER_SLOT};
use lean_genesis::ValidatorConfig;
use lean_keystore::{DEFAULT_KEYS_DIR, KeyStore, ValidatorKeyPair};
use lean_network::NetworkConfig;
use lean_network_config::load_network_files;
use lean_store::LeanStore;
use slot_clock::{SlotClock, SystemTimeSlotClock};
use ssz_types::VariableList;
use store::database::interface::BeaconNodeBackend;
use tracing::info;
use tree_hash::TreeHash;
use types::{EthSpec, Slot};

use validators::build_validators_from_config;

/// Input paths and identifiers required to build the lean client runtime.
pub struct LeanClientPaths {
    pub data_dir: PathBuf,
    pub config_path: PathBuf,
    pub validators_path: PathBuf,
    pub nodes_path: PathBuf,
    pub node_id: String,
    pub node_key_path: PathBuf,
    pub genesis_json_path: Option<PathBuf>,
}

/// Runtime resources required by the lean client services.
pub struct LeanClientResources<E: EthSpec> {
    pub slot_clock: SystemTimeSlotClock,
    pub db: Arc<BeaconNodeBackend<E>>,
    pub validator_key_pair: ValidatorKeyPair,
    pub validator_index: u64,
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
        node_key_path,
        genesis_json_path,
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

    // Load network config first to get validators from config.yaml
    let config_info = load_network_files(&config_path, &nodes_path)
        .map_err(|e| format!("Failed to load network config: {}", e))?;

    // Build validators from config.yaml GENESIS_VALIDATORS instead of keystore
    let validators_list = build_validators_from_config(&config_info.config_bytes)?;

    info!(
        total_validators = validators_list.len(),
        "Loaded validators from config.yaml"
    );

    if validators_list.is_empty() {
        return Err(
            "No validators found in config.yaml GENESIS_VALIDATORS. Please check configuration."
                .to_string(),
        );
    }

    // Extract genesis_time from genesis.json if available, otherwise use default (0)
    let genesis_time = if let Some(path) = &genesis_json_path {
        match std::fs::read(path) {
            Ok(bytes) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
                Ok(json) => json
                    .get("config")
                    .and_then(|c| c.get("genesis_time"))
                    .and_then(|t| {
                        t.as_str()
                            .and_then(|s| s.parse::<u64>().ok())
                            .or_else(|| t.as_u64())
                    })
                    .inspect(|&time| info!("Using genesis_time from genesis.json: {}", time))
                    .unwrap_or(0),
                Err(e) => {
                    info!(
                        "Failed to parse genesis.json: {}, using default genesis_time=0",
                        e
                    );
                    0
                }
            },
            Err(e) => {
                info!(
                    "Failed to read genesis.json: {}, using default genesis_time=0",
                    e
                );
                0
            }
        }
    } else {
        0
    };

    // Try to load genesis state from SSZ, otherwise generate fresh
    let _genesis_ssz_path = genesis_json_path
        .as_ref()
        .and_then(|json_path| json_path.parent().map(|parent| parent.join("genesis.ssz")));

    // Generate fresh genesis state to align with spec logic, ignoring any existing genesis.ssz.
    info!("Forcing fresh genesis state generation (ignoring genesis.ssz to align with spec)");

    let validators = VariableList::new(validators_list)
        .map_err(|e| format!("Failed to create validators list: {:?}", e))?;

    let genesis_state = LeanState::<E>::generate_genesis(genesis_time, validators);

    // Calculate the Genesis State Root
    let genesis_state_root = genesis_state.tree_hash_root();

    // Construct the Genesis Block with the populated state_root.
    // Matches the spec where the Head Block Header includes the Genesis State Root.
    let genesis_block = LeanBlock {
        slot: genesis_state.slot,
        proposer_index: genesis_state.latest_block_header.proposer_index.0, // Unwrap ValidatorIndex
        parent_root: genesis_state.latest_block_header.parent_root,
        state_root: genesis_state_root,
        body: LeanBlockBody {
            attestations: VariableList::empty(),
        },
    };

    let genesis_root = genesis_block.tree_hash_root();

    // Save the Genesis Block as the initial Head/Safe Target.
    lean_store
        .save_block(genesis_root, &genesis_block)
        .map_err(|e| format!("Failed to save genesis block: {}", e))?;
    lean_store
        .save_head_root(genesis_root)
        .map_err(|e| format!("Failed to set head root: {}", e))?;
    lean_store
        .save_safe_target(genesis_root)
        .map_err(|e| format!("Failed to set safe target: {}", e))?;

    info!(
        slot = genesis_state.slot.0,
        genesis_time = genesis_state.config.genesis_time,
        validators_count = genesis_state.validators.len(),
        genesis_root = ?genesis_root,
        "Initialized genesis state with validators"
    );

    lean_store
        .save_state(&genesis_state)
        .map_err(|e| format!("Failed to save genesis state to database: {}", e))?;
    info!(
        genesis_root = ?genesis_root,
        "Saved genesis state to database"
    );

    let slot_clock = SystemTimeSlotClock::new(
        Slot::new(0),
        Duration::from_secs(genesis_state.config.genesis_time),
        Duration::from_secs(SECONDS_PER_SLOT),
    );

    let validator_assignments = validator_config.validator_assignments();
    let (start_index, end_index) = validator_assignments
        .get(&node_id)
        .ok_or_else(|| format!("Node ID '{}' not found in validator config", node_id))?;

    if *start_index >= *end_index {
        return Err(format!(
            "Node ID '{}' has no validators assigned (start={}, end={})",
            node_id, start_index, end_index
        ));
    }

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

    if end_index - start_index != 1 {
        return Err(format!(
            "Node ID '{}' must be assigned to exactly one validator, found range [{} , {})",
            node_id, start_index, end_index
        ));
    }

    let validator_index = *start_index;

    let validator_key_pair = keystore.load_key_pair(validator_index).map_err(|e| {
        format!(
            "Failed to load keystore for validator index {}: {}",
            validator_index, e
        )
    })?;

    info!(
        validator_index,
        keystore_dir = ?keystore_dir,
        "Loaded XMSS key pair for validator"
    );

    let listen_port = validator_config
        .validators
        .iter()
        .find(|v| v.name == node_id)
        .and_then(|v| v.enr_fields.as_ref())
        .and_then(|e| e.quic)
        .unwrap_or(9000);

    info!(
        config = ?config_info,
        validators = ?validators_path,
        nodes = ?nodes_path,
        listen_port,
        node_id,
        bootstrap_nodes = config_info.bootstrap_enrs.len(),
        "Lean node configuration loaded"
    );

    let node_key_bytes = load_node_key(&node_key_path)?;

    let network_name = "devnet0".to_string();

    info!(network_name = %network_name, "Resolved network name");

    let network_config = NetworkConfig::new(listen_port, network_name.clone())
        .with_bootstrap_nodes(config_info.bootstrap_enrs)
        .with_node_key(node_key_bytes);

    Ok(LeanClientResources {
        slot_clock,
        db,
        validator_key_pair,
        validator_index,
        keystore,
        network_config,
    })
}

fn load_node_key(path: &Path) -> Result<Vec<u8>, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read libp2p private key from {:?}: {}", path, e))?;
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        return Err(format!("Libp2p private key file {:?} is empty", path));
    }
    let hex_str = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let key_bytes = hex::decode(hex_str)
        .map_err(|e| format!("Invalid hex in libp2p private key {:?}: {}", path, e))?;
    if key_bytes.len() != 32 {
        return Err(format!(
            "Libp2p private key {:?} must be 32 bytes, found {} bytes",
            path,
            key_bytes.len()
        ));
    }
    Ok(key_bytes)
}
