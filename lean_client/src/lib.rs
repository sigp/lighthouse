pub mod cli;
use lean_genesis::ValidatorConfig;
use lean_keystore::{KeyStore, ValidatorKeyPair};
use lean_validator_service::ValidatorService;
use lean_network::{load_bootstrap_nodes, NetworkConfig, NetworkService};
use lean_consensus::lean_state::LeanState;
use lean_store::LeanStore;
use slot_clock::{SlotClock, SystemTimeSlotClock};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use store::database::interface::BeaconNodeBackend as LeanBackend;
use task_executor::TaskExecutor;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tracing::info;
use types::{EthSpec, Slot};

pub struct ProductionLeanClient<E: EthSpec> {
    slot_clock: SystemTimeSlotClock,
    executor: TaskExecutor,
    db: Arc<LeanBackend<E>>,
    validator_key_pair: Option<ValidatorKeyPair>,
    validators_dir: PathBuf,
    nodes_path: PathBuf,
    node_id: String,
}

impl<E: EthSpec> ProductionLeanClient<E> {
    pub async fn new(
        executor: TaskExecutor,
        data_dir: PathBuf,
        config_path: PathBuf,
        validators_path: PathBuf,
        nodes_path: PathBuf,
        node_id: String,
    ) -> Result<Self, String> {
        // Ensure data directory exists
        fs::create_dir_all(&data_dir)
            .map_err(|e| format!("Failed to create data directory {:?}: {}", data_dir, e))?;

        // Initialize database first
        let db_path = data_dir.join("lean_db");
        let store_config = store::StoreConfig::default();
        let db = Arc::new(
            store::database::interface::BeaconNodeBackend::open(&store_config, &db_path)
                .map_err(|e| format!("Failed to open database: {:?}", e))?
        );

        // Create lean store for database operations
        let lean_store = LeanStore::new(db.clone());

        // Always start from genesis - never load from database
        let mut genesis_state = LeanState::<E>::genesis_default();

        // Set genesis_time to current time so slot clock starts at 0
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("Failed to get current time: {}", e))?
            .as_secs();

        genesis_state.config.genesis_time = current_time;

        info!(
            slot = genesis_state.slot.0,
            genesis_time = genesis_state.config.genesis_time,
            validators_count = genesis_state.validators.len(),
            "Initialized genesis state (always fresh start)"
        );

        // Save genesis state to database
        lean_store.save_state(&genesis_state)
            .map_err(|e| format!("Failed to save genesis state to database: {}", e))?;
        info!("Saved genesis state to database");

        // Create slot clock from genesis state config
        let slot_clock = SystemTimeSlotClock::new(
            Slot::new(0), // genesis slot is always 0
            Duration::from_secs(genesis_state.config.genesis_time),
            Duration::from_secs(genesis_state.config.seconds_per_slot),
        );

        // Load validator configuration to find validator index for this node
        let validator_config = ValidatorConfig::load_from_file(&validators_path)
            .map_err(|e| format!("Failed to load validator config from {:?}: {}", validators_path, e))?;

        // Find validator index range for this node_id
        let validator_assignments = validator_config.validator_assignments();
        let (start_index, _end_index) = validator_assignments
            .get(&node_id)
            .ok_or_else(|| format!("Node ID '{}' not found in validator config", node_id))?;

        info!(
            node_id = node_id,
            validator_start_index = start_index,
            validator_count = validator_config.validators.iter().find(|v| v.name == node_id).map(|v| v.count).unwrap_or(0),
            "Found validator assignment for node"
        );

        // Load keystore - assume it's in the same directory as validators.yaml
        let validators_dir = validators_path.parent()
            .ok_or_else(|| "validators.yaml path has no parent directory".to_string())?;
        // Try common keystore directory names
        let keystore_dir = validators_dir.join("hash-sig-keys");
        let keystore = KeyStore::new(keystore_dir.clone());

        // Load the private key for the first validator index assigned to this node
        let validator_key_pair = keystore.load_key_pair(*start_index)
            .map_err(|e| format!("Failed to load keystore for validator index {}: {}", start_index, e))?;

        info!(
            validator_index = start_index,
            keystore_dir = ?keystore_dir,
            "Loaded XMSS key pair from keystore"
        );

        info!(
            config = ?config_path,
            validators = ?validators_path,
            nodes = ?nodes_path,
            node_id = node_id,
            "Lean node configuration loaded"
        );

        Ok(Self {
            slot_clock,
            executor,
            db,
            validator_key_pair: Some(validator_key_pair),
            validators_dir: validators_dir.to_path_buf(),
            nodes_path: nodes_path.clone(),
            node_id: node_id.clone(),
        })
    }

    pub async fn start_service(&mut self, validators_path: PathBuf) -> Result<(), String> {
        // Create channels for bidirectional communication
        // network_recv: network -> validator service (incoming messages)
        let (network_recv_tx, network_recv_rx) = mpsc::unbounded_channel();
        // network_send: validator service -> network (outgoing messages)
        let (network_send_tx, network_send_rx) = mpsc::unbounded_channel();

        info!("Starting network service");

        // Load bootstrap nodes from nodes.yaml using ENR records
        let bootstrap_nodes = load_bootstrap_nodes(&self.nodes_path)
            .map_err(|e| format!("Failed to load bootstrap nodes: {}", e))?;

        info!("Loaded {} bootstrap nodes from {:?}", bootstrap_nodes.len(), &self.nodes_path);

        // Load validator config to get the QUIC port for this node
        let validator_config = ValidatorConfig::load_from_file(&validators_path)
            .map_err(|e| format!("Failed to load validator config: {}", e))?;

        // Find the QUIC port for this node from ENR fields
        let listen_port = validator_config.validators.iter()
            .find(|v| v.name == self.node_id)
            .and_then(|v| v.enr_fields.as_ref())
            .and_then(|e| e.quic)
            .unwrap_or(9000); // Default to 9000 if not found

        info!("Using listen port {} for this node", listen_port);

        let network_config = NetworkConfig::new(listen_port)
            .with_bootstrap_nodes(bootstrap_nodes);

        let network_service = NetworkService::<E>::new(network_config, network_recv_tx, network_send_rx)
            .map_err(|e| format!("Failed to create network service: {}", e))?;
        self.executor.spawn(network_service.start(), "network_service");

        info!("Starting validator service");
        let validator_key_pair = self.validator_key_pair.take()
            .ok_or_else(|| "Validator key pair not loaded".to_string())?;

        // Create keystore for loading validator public keys
        let keystore = KeyStore::new(self.validators_dir.join("hash-sig-keys"));

        let validator_service = ValidatorService::new(
            self.slot_clock.clone(),
            network_recv_rx,
            network_send_tx,
            self.db.clone(),
            validator_key_pair,
            keystore,
        );

        // Spawn validator service directly (no conductor wrapper needed)
        self.executor.spawn(validator_service.run(), "validator_service");

        Ok(())
    }
}
