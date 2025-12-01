pub mod cli;
pub mod config;

pub use config::Config;

use std::sync::Arc;

use crate::config::Config as LeanClientConfig;
use environment::RuntimeContext;
use lean_config::{LeanClientPaths, initialize as load_runtime};
use lean_keystore::{KeyStore, ValidatorKeyPair};
use lean_network::{NetworkConfig, NetworkService};
use lean_validator_service::ValidatorService;
use slot_clock::SystemTimeSlotClock;
use store::database::interface::BeaconNodeBackend as LeanBackend;
use tokio::sync::mpsc;
use tracing::info;
use types::EthSpec;

pub struct ProductionLeanClient<E: EthSpec> {
    context: RuntimeContext<E>,
    slot_clock: SystemTimeSlotClock,
    db: Arc<LeanBackend<E>>,
    validator_key_pair: Option<ValidatorKeyPair>,
    validator_index: u64,
    keystore: Option<KeyStore>,
    network_config: NetworkConfig,
}

impl<E: EthSpec> ProductionLeanClient<E> {
    pub async fn new(context: RuntimeContext<E>, config: LeanClientConfig) -> Result<Self, String> {
        let resources = load_runtime::<E>(LeanClientPaths::from(config))?;

        info!("Lean client runtime resources prepared");

        Ok(Self {
            context,
            slot_clock: resources.slot_clock,
            db: resources.db,
            validator_key_pair: Some(resources.validator_key_pair),
            validator_index: resources.validator_index,
            keystore: Some(resources.keystore),
            network_config: resources.network_config,
        })
    }

    pub async fn start_service(&mut self) -> Result<(), String> {
        let (network_recv_tx, network_recv_rx) = mpsc::unbounded_channel();
        let (network_send_tx, network_send_rx) = mpsc::unbounded_channel();

        info!("Starting network service");
        let network_service = NetworkService::<E>::new(
            self.network_config.clone(),
            network_recv_tx,
            network_send_rx,
        )
        .map_err(|e| format!("Failed to create network service: {}", e))?;
        self.context
            .executor
            .clone_with_name("lean_network_service".into())
            .spawn(network_service.start(), "network_service");

        info!("Starting validator service");
        let validator_key_pair = self
            .validator_key_pair
            .take()
            .ok_or_else(|| "Validator key pair not loaded".to_string())?;
        let keystore = self
            .keystore
            .take()
            .ok_or_else(|| "Keystore not initialized".to_string())?;

        let validator_service = ValidatorService::new(
            self.slot_clock.clone(),
            network_recv_rx,
            network_send_tx,
            self.db.clone(),
            self.validator_index,
            validator_key_pair,
            keystore,
        )?;

        self.context
            .executor
            .clone_with_name("lean_validator_service".into())
            .spawn(validator_service.run(), "validator_service");

        Ok(())
    }
}
