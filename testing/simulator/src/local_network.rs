use node_test_rig::{
    environment::RuntimeContext,
    eth2::{types::StateId, BeaconNodeHttpClient},
    ClientConfig, LocalBeaconNode, LocalValidatorClient, ValidatorConfig, ValidatorFiles,
};
use parking_lot::RwLock;
use sensitive_url::SensitiveUrl;
use std::{
    ops::Deref,
    time::{SystemTime, UNIX_EPOCH},
};
use std::{sync::Arc, time::Duration};
use types::{Epoch, EthSpec};

const BOOTNODE_PORT: u16 = 42424;
pub const INVALID_ADDRESS: &str = "http://127.0.0.1:42423";

/// Helper struct to reduce `Arc` usage.
pub struct Inner<E: EthSpec> {
    pub context: RuntimeContext<E>,
    pub beacon_nodes: RwLock<Vec<LocalBeaconNode<E>>>,
    pub validator_clients: RwLock<Vec<LocalValidatorClient<E>>>,
}

/// Represents a set of interconnected `LocalBeaconNode` and `LocalValidatorClient`.
///
/// Provides functions to allow adding new beacon nodes and validators.
pub struct LocalNetwork<E: EthSpec> {
    inner: Arc<Inner<E>>,
}

impl<E: EthSpec> Clone for LocalNetwork<E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<E: EthSpec> Deref for LocalNetwork<E> {
    type Target = Inner<E>;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl<E: EthSpec> LocalNetwork<E> {
    /// Creates a new network with a single `BeaconNode`.
    pub async fn new(
        context: RuntimeContext<E>,
        mut beacon_config: ClientConfig,
    ) -> Result<Self, String> {
        beacon_config.network.discovery_port = BOOTNODE_PORT;
        beacon_config.network.libp2p_port = BOOTNODE_PORT;
        beacon_config.network.enr_udp_port = Some(BOOTNODE_PORT);
        beacon_config.network.enr_tcp_port = Some(BOOTNODE_PORT);
        let beacon_node =
            LocalBeaconNode::production(context.service_context("boot_node".into()), beacon_config)
                .await?;
        Ok(Self {
            inner: Arc::new(Inner {
                context,
                beacon_nodes: RwLock::new(vec![beacon_node]),
                validator_clients: RwLock::new(vec![]),
            }),
        })
    }

    /// Returns the number of beacon nodes in the network.
    ///
    /// Note: does not count nodes that are external to this `LocalNetwork` that may have connected
    /// (e.g., another Lighthouse process on the same machine.)
    pub fn beacon_node_count(&self) -> usize {
        self.beacon_nodes.read().len()
    }

    /// Returns the number of validator clients in the network.
    ///
    /// Note: does not count nodes that are external to this `LocalNetwork` that may have connected
    /// (e.g., another Lighthouse process on the same machine.)
    pub fn validator_client_count(&self) -> usize {
        self.validator_clients.read().len()
    }

    /// Adds a beacon node to the network, connecting to the 0'th beacon node via ENR.
    pub async fn add_beacon_node(&self, mut beacon_config: ClientConfig) -> Result<(), String> {
        let self_1 = self.clone();
        println!("Adding beacon node..");
        {
            let read_lock = self.beacon_nodes.read();

            let boot_node = read_lock.first().expect("should have at least one node");

            beacon_config.network.boot_nodes_enr.push(
                boot_node
                    .client
                    .enr()
                    .expect("bootnode must have a network"),
            );
            let count = self.beacon_node_count() as u16;
            beacon_config.network.discovery_port = BOOTNODE_PORT + count;
            beacon_config.network.libp2p_port = BOOTNODE_PORT + count;
            beacon_config.network.enr_udp_port = Some(BOOTNODE_PORT + count);
            beacon_config.network.enr_tcp_port = Some(BOOTNODE_PORT + count);
        }

        let mut write_lock = self_1.beacon_nodes.write();
        let index = write_lock.len();

        let beacon_node = LocalBeaconNode::production(
            self.context.service_context(format!("node_{}", index)),
            beacon_config,
        )
        .await?;
        write_lock.push(beacon_node);
        Ok(())
    }

    /// Adds a validator client to the network, connecting it to the beacon node with index
    /// `beacon_node`.
    pub async fn add_validator_client(
        &self,
        mut validator_config: ValidatorConfig,
        beacon_node: usize,
        validator_files: ValidatorFiles,
        invalid_first_beacon_node: bool, //to test beacon node fallbacks
    ) -> Result<(), String> {
        let context = self
            .context
            .service_context(format!("validator_{}", beacon_node));
        let self_1 = self.clone();
        let socket_addr = {
            let read_lock = self.beacon_nodes.read();
            let beacon_node = read_lock
                .get(beacon_node)
                .ok_or_else(|| format!("No beacon node for index {}", beacon_node))?;
            beacon_node
                .client
                .http_api_listen_addr()
                .expect("Must have http started")
        };

        let beacon_node = SensitiveUrl::parse(
            format!("http://{}:{}", socket_addr.ip(), socket_addr.port()).as_str(),
        )
        .unwrap();
        validator_config.beacon_nodes = if invalid_first_beacon_node {
            vec![SensitiveUrl::parse(INVALID_ADDRESS).unwrap(), beacon_node]
        } else {
            vec![beacon_node]
        };
        let validator_client = LocalValidatorClient::production_with_insecure_keypairs(
            context,
            validator_config,
            validator_files,
        )
        .await?;
        self_1.validator_clients.write().push(validator_client);
        Ok(())
    }

    /// For all beacon nodes in `Self`, return a HTTP client to access each nodes HTTP API.
    pub fn remote_nodes(&self) -> Result<Vec<BeaconNodeHttpClient>, String> {
        let beacon_nodes = self.beacon_nodes.read();

        beacon_nodes
            .iter()
            .map(|beacon_node| beacon_node.remote_node())
            .collect()
    }

    /// Return current epoch of bootnode.
    pub async fn bootnode_epoch(&self) -> Result<Epoch, String> {
        let nodes = self.remote_nodes().expect("Failed to get remote nodes");
        let bootnode = nodes.first().expect("Should contain bootnode");
        bootnode
            .get_beacon_states_finality_checkpoints(StateId::Head)
            .await
            .map_err(|e| format!("Cannot get head: {:?}", e))
            .map(|body| body.unwrap().data.finalized.epoch)
    }

    pub async fn duration_to_genesis(&self) -> Duration {
        let nodes = self.remote_nodes().expect("Failed to get remote nodes");
        let bootnode = nodes.first().expect("Should contain bootnode");
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let genesis_time = Duration::from_secs(
            bootnode
                .get_beacon_genesis()
                .await
                .unwrap()
                .data
                .genesis_time,
        );
        genesis_time - now
    }
}
