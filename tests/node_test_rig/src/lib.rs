use beacon_node::{beacon_chain::BeaconChainTypes, Client, ProductionBeaconNode};
use environment::RuntimeContext;
use futures::Future;
use remote_beacon_node::RemoteBeaconNode;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tempdir::TempDir;
use types::EthSpec;
use validator_client::{validator_directory::ValidatorDirectoryBuilder, ProductionValidatorClient};

pub use beacon_node::{ClientConfig, ClientGenesis, ProductionClient};
pub use environment;
pub use validator_client::Config as ValidatorConfig;

/// Provides a beacon node that is running in the current process (i.e., local). Useful for testing
/// purposes.
pub struct LocalBeaconNode<T> {
    pub client: T,
    pub datadir: TempDir,
}

impl<E: EthSpec> LocalBeaconNode<ProductionClient<E>> {
    /// Starts a new, production beacon node.
    pub fn production(context: RuntimeContext<E>, mut client_config: ClientConfig) -> Self {
        // Creates a temporary directory that will be deleted once this `TempDir` is dropped.
        let datadir = TempDir::new("lighthouse_node_test_rig")
            .expect("should create temp directory for client datadir");

        client_config.data_dir = datadir.path().into();
        client_config.network.network_dir = PathBuf::from(datadir.path()).join("network");

        let client = ProductionBeaconNode::new(context, client_config)
            .wait()
            .expect("should build production client")
            .into_inner();

        LocalBeaconNode { client, datadir }
    }
}

impl<T: BeaconChainTypes> LocalBeaconNode<Client<T>> {
    /// Returns a `RemoteBeaconNode` that can connect to `self`. Useful for testing the node as if
    /// it were external this process.
    pub fn remote_node(&self) -> Result<RemoteBeaconNode<T::EthSpec>, String> {
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
    client_config.rest_api.port = 0;
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

pub struct LocalValidatorClient<T: EthSpec> {
    pub client: ProductionValidatorClient<T>,
    pub datadir: TempDir,
}

impl<E: EthSpec> LocalValidatorClient<E> {
    pub fn production_with_insecure_keypairs(
        context: RuntimeContext<E>,
        config: ValidatorConfig,
        keypair_indices: &[usize],
    ) -> Self {
        // Creates a temporary directory that will be deleted once this `TempDir` is dropped.
        let datadir = TempDir::new("lighthouse-beacon-node")
            .expect("should create temp directory for client datadir");

        keypair_indices.iter().for_each(|i| {
            ValidatorDirectoryBuilder::default()
                .spec(context.eth2_config.spec.clone())
                .full_deposit_amount()
                .expect("should set full deposit amount")
                .insecure_keypairs(*i)
                .create_directory(PathBuf::from(datadir.path()))
                .expect("should create directory")
                .write_keypair_files()
                .expect("should write keypair files")
                .write_eth1_data_file()
                .expect("should write eth1 data file")
                .build()
                .expect("should build dir");
        });

        Self::new(context, config, datadir)
    }

    pub fn production(context: RuntimeContext<E>, config: ValidatorConfig) -> Self {
        // Creates a temporary directory that will be deleted once this `TempDir` is dropped.
        let datadir = TempDir::new("lighthouse-validator")
            .expect("should create temp directory for client datadir");

        Self::new(context, config, datadir)
    }

    fn new(context: RuntimeContext<E>, mut config: ValidatorConfig, datadir: TempDir) -> Self {
        config.data_dir = datadir.path().into();

        let client = ProductionValidatorClient::new(context, config)
            .wait()
            .expect("should start validator client");

        client
            .start_service()
            .expect("should start validator client");

        Self { client, datadir }
    }
}
