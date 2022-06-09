use node_test_rig::{
    environment::RuntimeContext,
    eth2::{types::StateId, BeaconNodeHttpClient},
    ClientConfig, LocalBeaconNode, LocalValidatorClient, MockExecutionConfig, MockServer,
    MockServerConfig, ValidatorConfig, ValidatorFiles,
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

pub const EXECUTION_PORT: u16 = 4000;

pub const TERMINAL_DIFFICULTY: u64 = 3200;
pub const TERMINAL_BLOCK: u64 = 32;

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
        execution_layer_config: Option<MockExecutionConfig>,
    ) -> Result<Self, String> {
        beacon_config.network.discovery_port = BOOTNODE_PORT;
        beacon_config.network.libp2p_port = BOOTNODE_PORT;
        beacon_config.network.enr_udp_port = Some(BOOTNODE_PORT);
        beacon_config.network.enr_tcp_port = Some(BOOTNODE_PORT);
        beacon_config.network.discv5_config.table_filter = |_| true;

        let execution_node = if let Some(config) = execution_layer_config {
            Some(MockServer::new_with_config(
                &context.executor.handle().unwrap(),
                config,
            ))
        } else {
            None
        };
        let beacon_node = LocalBeaconNode::production(
            context.service_context("boot_node".into()),
            beacon_config,
            execution_node,
        )
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
        let execution_node = {
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
            beacon_config.network.discv5_config.table_filter = |_| true;

            if boot_node.execution_node.is_some() {
                let config = MockExecutionConfig {
                    server_config: MockServerConfig {
                        listen_port: EXECUTION_PORT + count,
                        ..Default::default()
                    },
                    terminal_block: TERMINAL_BLOCK,
                    terminal_difficulty: TERMINAL_DIFFICULTY.into(),
                    ..Default::default()
                };
                Some(MockServer::new_with_config(
                    &self_1.inner.context.executor.handle().unwrap(),
                    config,
                ))
            } else {
                None
            }
        };

        // We create the beacon node without holding the lock, so that the lock isn't held
        // across the await. This is only correct if this function never runs in parallel
        // with itself (which at the time of writing, it does not).
        let index = self_1.beacon_nodes.read().len();
        let beacon_node = LocalBeaconNode::production(
            self.context.service_context(format!("node_{}", index)),
            beacon_config,
            execution_node,
        )
        .await?;
        self_1.beacon_nodes.write().push(beacon_node);
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

    pub fn mine_pow_blocks(&self, block_number: u64) -> Result<(), String> {
        let beacon_nodes = self.beacon_nodes.read();
        for bn in beacon_nodes.iter() {
            if let Some(execution_node) = &bn.execution_node {
                let mut block_gen = execution_node.ctx.execution_block_generator.write();
                if let Err(e) = block_gen.insert_pow_block(block_number) {
                    dbg!(e);
                } else {
                    println!("Successfully inserted pow block {}", block_number);
                }
            }
        }
        Ok(())
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
