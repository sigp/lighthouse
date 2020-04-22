//! Provides easy ways to run a beacon node or validator client in-process.
//!
//! Intended to be used for testing and simulation purposes. Not for production.

use beacon_node::ProductionBeaconNode;
use environment::RuntimeContext;
use futures::Future;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tempdir::TempDir;
use types::EthSpec;
use validator_client::{KeySource, ProductionValidatorClient};

pub use beacon_node::{ClientConfig, ClientGenesis, ProductionClient};
pub use environment;
pub use remote_beacon_node::RemoteBeaconNode;
pub use validator_client::Config as ValidatorConfig;

/// Provids a beacon node that is running in the current process on a given tokio executor (it
/// is _local_ to this process).
///
/// Intended for use in testing and simulation. Not for production.
pub struct LocalBeaconNode<E: EthSpec> {
    pub client: ProductionClient<E>,
    pub datadir: TempDir,
}

impl<E: EthSpec> LocalBeaconNode<E> {
    /// Starts a new, production beacon node on the tokio runtime in the given `context`.
    ///
    /// The node created is using the same types as the node we use in production.
    pub fn production(
        context: RuntimeContext<E>,
        mut client_config: ClientConfig,
    ) -> impl Future<Item = Self, Error = String> {
        // Creates a temporary directory that will be deleted once this `TempDir` is dropped.
        let datadir = TempDir::new("lighthouse_node_test_rig")
            .expect("should create temp directory for client datadir");

        client_config.data_dir = datadir.path().into();
        client_config.network.network_dir = PathBuf::from(datadir.path()).join("network");

        ProductionBeaconNode::new(context, client_config).map(move |client| Self {
            client: client.into_inner(),
            datadir,
        })
    }
}

impl<E: EthSpec> LocalBeaconNode<E> {
    /// Returns a `RemoteBeaconNode` that can connect to `self`. Useful for testing the node as if
    /// it were external this process.
    pub fn remote_node(&self) -> Result<RemoteBeaconNode<E>, String> {
        let socket_addr = self
            .client
            .http_listen_addr()
            .ok_or_else(|| "A remote beacon node must have a http server".to_string())?;
        Ok(RemoteBeaconNode::new(format!(
            "http://{}:{}",
            socket_addr.ip(),
            socket_addr.port()
        ))?)
    }
}

pub fn testing_client_config() -> ClientConfig {
    let mut client_config = ClientConfig::default();

    // Setting ports to `0` means that the OS will choose some available port.
    client_config.network.libp2p_port = 0;
    client_config.network.discovery_port = 0;
    client_config.rest_api.enabled = true;
    client_config.rest_api.port = 0;
    client_config.websocket_server.enabled = true;
    client_config.websocket_server.port = 0;

    client_config.dummy_eth1_backend = true;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("should get system time")
        .as_secs();

    client_config.genesis = ClientGenesis::Interop {
        validator_count: 8,
        genesis_time: now,
    };

    client_config.dummy_eth1_backend = true;

    client_config
}

/// Provides a validator client that is running in the current process on a given tokio executor (it
/// is _local_ to this process).
///
/// Intended for use in testing and simulation. Not for production.
pub struct LocalValidatorClient<T: EthSpec> {
    pub client: ProductionValidatorClient<T>,
    pub datadir: TempDir,
}

impl<E: EthSpec> LocalValidatorClient<E> {
    /// Creates a validator client with insecure deterministic keypairs. The validator directories
    /// are created in a temp dir then removed when the process exits.
    ///
    /// The validator created is using the same types as the node we use in production.
    pub fn production_with_insecure_keypairs(
        context: RuntimeContext<E>,
        mut config: ValidatorConfig,
        keypair_indices: &[usize],
    ) -> impl Future<Item = Self, Error = String> {
        // Creates a temporary directory that will be deleted once this `TempDir` is dropped.
        let datadir = TempDir::new("lighthouse-beacon-node")
            .expect("should create temp directory for client datadir");

        config.key_source = KeySource::InsecureKeypairs(keypair_indices.to_vec());

        Self::new(context, config, datadir)
    }

    /// Creates a validator client that attempts to read keys from the default data dir.
    ///
    /// - The validator created is using the same types as the node we use in production.
    /// - It is recommended to use `production_with_insecure_keypairs` for testing.
    pub fn production(
        context: RuntimeContext<E>,
        config: ValidatorConfig,
    ) -> impl Future<Item = Self, Error = String> {
        // Creates a temporary directory that will be deleted once this `TempDir` is dropped.
        let datadir = TempDir::new("lighthouse-validator")
            .expect("should create temp directory for client datadir");

        Self::new(context, config, datadir)
    }

    fn new(
        context: RuntimeContext<E>,
        mut config: ValidatorConfig,
        datadir: TempDir,
    ) -> impl Future<Item = Self, Error = String> {
        config.data_dir = datadir.path().into();

        ProductionValidatorClient::new(context, config).map(move |mut client| {
            client
                .start_service()
                .expect("should start validator services");
            Self { client, datadir }
        })
    }
}
