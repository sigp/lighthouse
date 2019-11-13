use beacon_node::{
    beacon_chain::BeaconChainTypes, Client, ClientConfig, ClientGenesis, ProductionBeaconNode,
    ProductionClient,
};
use environment::RuntimeContext;
use futures::Future;
use remote_beacon_node::RemoteBeaconNode;
use tempdir::TempDir;
use types::EthSpec;

pub use environment;

/// Provides a beacon node that is running in the current process. Useful for testing purposes.
pub struct LocalBeaconNode<T> {
    pub client: T,
    pub datadir: TempDir,
}

impl<E: EthSpec> LocalBeaconNode<ProductionClient<E>> {
    /// Starts a new, production beacon node.
    pub fn production(context: RuntimeContext<E>) -> Self {
        let (client_config, datadir) = testing_client_config();

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
        Ok(RemoteBeaconNode::new(
            self.client
                .http_listen_addr()
                .ok_or_else(|| "A remote beacon node must have a http server".to_string())?,
        )?)
    }
}

fn testing_client_config() -> (ClientConfig, TempDir) {
    // Creates a temporary directory that will be deleted once this `TempDir` is dropped.
    let tempdir = TempDir::new("lighthouse_node_test_rig")
        .expect("should create temp directory for client datadir");

    let mut client_config = ClientConfig::default();

    client_config.data_dir = tempdir.path().into();

    // Setting ports to `0` means that the OS will choose some available port.
    client_config.network.libp2p_port = 0;
    client_config.network.discovery_port = 0;
    client_config.rpc.port = 0;
    client_config.rest_api.port = 0;
    client_config.websocket_server.port = 0;

    client_config.genesis = ClientGenesis::Interop {
        validator_count: 8,
        genesis_time: 13_371_337,
    };

    client_config.dummy_eth1_backend = true;

    (client_config, tempdir)
}
