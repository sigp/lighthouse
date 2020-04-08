use futures::{Future, IntoFuture};
use node_test_rig::{
    environment::RuntimeContext, ClientConfig, LocalBeaconNode, LocalValidatorClient,
    RemoteBeaconNode, ValidatorConfig,
};
use parking_lot::RwLock;
use std::ops::Deref;
use std::sync::Arc;
use types::{Epoch, EthSpec};

const BOOTNODE_PORT: u16 = 42424;

/// Helper struct to reduce `Arc` usage.
pub struct Inner<E: EthSpec> {
    context: RuntimeContext<E>,
    beacon_nodes: RwLock<Vec<LocalBeaconNode<E>>>,
    validator_clients: RwLock<Vec<LocalValidatorClient<E>>>,
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
    pub fn new(
        context: RuntimeContext<E>,
        mut beacon_config: ClientConfig,
    ) -> impl Future<Item = Self, Error = String> {
        // Fix bootnode ports
        beacon_config.network.discovery_port = BOOTNODE_PORT;
        beacon_config.network.libp2p_port = BOOTNODE_PORT;
        LocalBeaconNode::production(context.service_context("boot_node".into()), beacon_config).map(
            |beacon_node| Self {
                inner: Arc::new(Inner {
                    context,
                    beacon_nodes: RwLock::new(vec![beacon_node]),
                    validator_clients: RwLock::new(vec![]),
                }),
            },
        )
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
    pub fn add_beacon_node(
        &self,
        mut beacon_config: ClientConfig,
    ) -> impl Future<Item = (), Error = String> {
        let self_1 = self.clone();
        println!("Adding beacon node..");
        self.beacon_nodes
            .read()
            .first()
            .map(|boot_node| {
                beacon_config.network.boot_nodes.push(
                    boot_node
                        .client
                        .enr()
                        .expect("bootnode must have a network"),
                );
            })
            .expect("should have at least one node");

        let index = self.beacon_nodes.read().len();

        LocalBeaconNode::production(
            self.context.service_context(format!("node_{}", index)),
            beacon_config,
        )
        .map(move |beacon_node| {
            self_1.beacon_nodes.write().push(beacon_node);
        })
    }

    /// Adds a validator client to the network, connecting it to the beacon node with index
    /// `beacon_node`.
    pub fn add_validator_client(
        &self,
        mut validator_config: ValidatorConfig,
        beacon_node: usize,
        keypair_indices: Vec<usize>,
    ) -> impl Future<Item = (), Error = String> {
        let index = self.validator_clients.read().len();
        let context = self.context.service_context(format!("validator_{}", index));
        let self_1 = self.clone();

        self.beacon_nodes
            .read()
            .get(beacon_node)
            .map(move |beacon_node| {
                let socket_addr = beacon_node
                    .client
                    .http_listen_addr()
                    .expect("Must have http started");

                validator_config.http_server =
                    format!("http://{}:{}", socket_addr.ip(), socket_addr.port());

                validator_config
            })
            .ok_or_else(|| format!("No beacon node for index {}", beacon_node))
            .into_future()
            .and_then(move |validator_config| {
                LocalValidatorClient::production_with_insecure_keypairs(
                    context,
                    validator_config,
                    &keypair_indices,
                )
            })
            .map(move |validator_client| self_1.validator_clients.write().push(validator_client))
    }

    /// For all beacon nodes in `Self`, return a HTTP client to access each nodes HTTP API.
    pub fn remote_nodes(&self) -> Result<Vec<RemoteBeaconNode<E>>, String> {
        let beacon_nodes = self.beacon_nodes.read();

        beacon_nodes
            .iter()
            .map(|beacon_node| beacon_node.remote_node())
            .collect()
    }

    /// Return current epoch of bootnode.
    pub fn bootnode_epoch(&self) -> impl Future<Item = Epoch, Error = String> {
        let nodes = self.remote_nodes().expect("Failed to get remote nodes");
        let bootnode = nodes.first().expect("Should contain bootnode");
        bootnode
            .http
            .beacon()
            .get_head()
            .map_err(|e| format!("Cannot get head: {:?}", e))
            .map(|head| head.finalized_slot.epoch(E::slots_per_epoch()))
    }
}
