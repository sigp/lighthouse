use node_test_rig::{
    environment::RuntimeContext,
    eth2::{types::StateId, BeaconNodeHttpClient},
    ClientConfig, LocalBeaconNode, LocalExecutionNode, LocalValidatorClient, MockExecutionConfig,
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
const QUIC_PORT: u16 = 43424;
pub const INVALID_ADDRESS: &str = "http://127.0.0.1:42423";

pub const EXECUTION_PORT: u16 = 4000;

pub const TERMINAL_DIFFICULTY: u64 = 6400;
pub const TERMINAL_BLOCK: u64 = 64;

/// Helper struct to reduce `Arc` usage.
pub struct Inner<E: EthSpec> {
    pub context: RuntimeContext<E>,
    pub beacon_nodes: RwLock<Vec<LocalBeaconNode<E>>>,
    pub proposer_nodes: RwLock<Vec<LocalBeaconNode<E>>>,
    pub validator_clients: RwLock<Vec<LocalValidatorClient<E>>>,
    pub execution_nodes: RwLock<Vec<LocalExecutionNode<E>>>,
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
    /// Creates a new network with a single `BeaconNode` and a connected `ExecutionNode`.
    pub async fn new(
        context: RuntimeContext<E>,
        mut beacon_config: ClientConfig,
    ) -> Result<Self, String> {
        beacon_config.network.set_ipv4_listening_address(
            std::net::Ipv4Addr::UNSPECIFIED,
            BOOTNODE_PORT,
            BOOTNODE_PORT,
            QUIC_PORT,
        );
        beacon_config.network.enr_udp4_port = Some(BOOTNODE_PORT.try_into().expect("non zero"));
        beacon_config.network.enr_tcp4_port = Some(BOOTNODE_PORT.try_into().expect("non zero"));
        beacon_config.network.discv5_config.table_filter = |_| true;

        let execution_node = if let Some(el_config) = &mut beacon_config.execution_layer {
            let mock_execution_config = MockExecutionConfig {
                server_config: MockServerConfig {
                    listen_port: EXECUTION_PORT,
                    ..Default::default()
                },
                terminal_block: TERMINAL_BLOCK,
                terminal_difficulty: TERMINAL_DIFFICULTY.into(),
                ..Default::default()
            };
            let execution_node = LocalExecutionNode::new(
                context.service_context("boot_node_el".into()),
                mock_execution_config,
            );
            el_config.default_datadir = execution_node.datadir.path().to_path_buf();
            el_config.secret_file = Some(execution_node.datadir.path().join("jwt.hex"));
            el_config.execution_endpoint =
                Some(SensitiveUrl::parse(&execution_node.server.url()).unwrap());
            vec![execution_node]
        } else {
            vec![]
        };

        let beacon_node =
            LocalBeaconNode::production(context.service_context("boot_node".into()), beacon_config)
                .await?;
        Ok(Self {
            inner: Arc::new(Inner {
                context,
                beacon_nodes: RwLock::new(vec![beacon_node]),
                proposer_nodes: RwLock::new(vec![]),
                execution_nodes: RwLock::new(execution_node),
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

    /// Returns the number of proposer nodes in the network.
    ///
    /// Note: does not count nodes that are external to this `LocalNetwork` that may have connected
    /// (e.g., another Lighthouse process on the same machine.)
    pub fn proposer_node_count(&self) -> usize {
        self.proposer_nodes.read().len()
    }

    /// Returns the number of validator clients in the network.
    ///
    /// Note: does not count nodes that are external to this `LocalNetwork` that may have connected
    /// (e.g., another Lighthouse process on the same machine.)
    pub fn validator_client_count(&self) -> usize {
        self.validator_clients.read().len()
    }

    /// Adds a beacon node to the network, connecting to the 0'th beacon node via ENR.
    pub async fn add_beacon_node(
        &self,
        mut beacon_config: ClientConfig,
        is_proposer: bool,
    ) -> Result<(), String> {
        let self_1 = self.clone();
        let count = self.beacon_node_count() as u16;
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
            let count = (self.beacon_node_count() + self.proposer_node_count()) as u16;
            let libp2p_tcp_port = BOOTNODE_PORT + count;
            let discv5_port = BOOTNODE_PORT + count;
            beacon_config.network.set_ipv4_listening_address(
                std::net::Ipv4Addr::UNSPECIFIED,
                libp2p_tcp_port,
                discv5_port,
                QUIC_PORT + count,
            );
            beacon_config.network.enr_udp4_port = Some(discv5_port.try_into().unwrap());
            beacon_config.network.enr_tcp4_port = Some(libp2p_tcp_port.try_into().unwrap());
            beacon_config.network.discv5_config.table_filter = |_| true;
            beacon_config.network.proposer_only = is_proposer;
        }
        if let Some(el_config) = &mut beacon_config.execution_layer {
            let config = MockExecutionConfig {
                server_config: MockServerConfig {
                    listen_port: EXECUTION_PORT + count,
                    ..Default::default()
                },
                terminal_block: TERMINAL_BLOCK,
                terminal_difficulty: TERMINAL_DIFFICULTY.into(),
                ..Default::default()
            };
            let execution_node = LocalExecutionNode::new(
                self.context.service_context(format!("node_{}_el", count)),
                config,
            );
            el_config.default_datadir = execution_node.datadir.path().to_path_buf();
            el_config.secret_file = Some(execution_node.datadir.path().join("jwt.hex"));
            el_config.execution_endpoint =
                Some(SensitiveUrl::parse(&execution_node.server.url()).unwrap());
            self.execution_nodes.write().push(execution_node);
        }

        // We create the beacon node without holding the lock, so that the lock isn't held
        // across the await. This is only correct if this function never runs in parallel
        // with itself (which at the time of writing, it does not).
        let beacon_node = LocalBeaconNode::production(
            self.context.service_context(format!("node_{}", count)),
            beacon_config,
        )
        .await?;
        if is_proposer {
            self_1.proposer_nodes.write().push(beacon_node);
        } else {
            self_1.beacon_nodes.write().push(beacon_node);
        }
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
        // If there is a proposer node for the same index, we will use that for proposing
        let proposer_socket_addr = {
            let read_lock = self.proposer_nodes.read();
            read_lock.get(beacon_node).map(|proposer_node| {
                proposer_node
                    .client
                    .http_api_listen_addr()
                    .expect("Must have http started")
            })
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

        // If we have a proposer node established, use it.
        if let Some(proposer_socket_addr) = proposer_socket_addr {
            let url = SensitiveUrl::parse(
                format!(
                    "http://{}:{}",
                    proposer_socket_addr.ip(),
                    proposer_socket_addr.port()
                )
                .as_str(),
            )
            .unwrap();
            validator_config.proposer_nodes = vec![url];
        }

        let validator_client = LocalValidatorClient::production_with_insecure_keypairs(
            context,
            validator_config,
            validator_files,
        )
        .await?;
        self_1.validator_clients.write().push(validator_client);
        Ok(())
    }

    pub async fn add_validator_client_with_fallbacks(
        &self,
        mut validator_config: ValidatorConfig,
        validator_index: usize,
        beacon_nodes: Vec<usize>,
        validator_files: ValidatorFiles,
    ) -> Result<(), String> {
        let context = self
            .context
            .service_context(format!("validator_{}", validator_index));
        let self_1 = self.clone();
        let mut beacon_node_urls = vec![];
        for beacon_node in beacon_nodes {
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
            beacon_node_urls.push(beacon_node);
        }

        validator_config.beacon_nodes = beacon_node_urls;

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
        let proposer_nodes = self.proposer_nodes.read();

        beacon_nodes
            .iter()
            .chain(proposer_nodes.iter())
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
        let execution_nodes = self.execution_nodes.read();
        for execution_node in execution_nodes.iter() {
            let mut block_gen = execution_node.server.ctx.execution_block_generator.write();
            block_gen.insert_pow_block(block_number)?;
            println!("Mined pow block {}", block_number);
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
