//! Network configuration for the lean client
//!
//! This crate provides network configuration management for the lean client.
//! It defines the configuration of lean networks (e.g., testnets, mainnet).
//!
//! The crate intentionally avoids importing consensus types and only deals with
//! raw bytes and configuration data. This keeps the crate simple and decoupled from
//! the consensus layer.

mod bootstrap;
mod config;
mod genesis;
mod loader;

pub use bootstrap::{load_bootstrap_nodes, parse_bootstrap_nodes_yaml};
pub use config::{LeanNetworkConfig, NetworkConfigBytes};
pub use genesis::GenesisStateBytes;
pub use loader::{ConfigInfo, load_network_files};

/// File names for network configuration
pub const CONFIG_FILE: &str = "config.yaml";
pub const BOOTSTRAP_NODES_FILE: &str = "bootstrap_nodes.yaml";
pub const GENESIS_STATE_FILE: &str = "genesis.ssz";
pub const GENESIS_STATE_ZIP_FILE: &str = "genesis.ssz.zip";

pub const DEFAULT_NETWORK: &str = "mainnet";
