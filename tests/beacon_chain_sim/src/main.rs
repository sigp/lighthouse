use node_test_rig::{
    environment::{Environment, EnvironmentBuilder, RuntimeContext},
    testing_client_config, ClientConfig, ClientGenesis, LocalBeaconNode, LocalValidatorClient,
    ProductionClient, ValidatorConfig,
};
use std::time::{SystemTime, UNIX_EPOCH};
use types::EthSpec;

pub type BeaconNode<E> = LocalBeaconNode<ProductionClient<E>>;

fn main() {
    let nodes = 4;
    let validators_per_node = 64 / nodes;

    match simulation(nodes, validators_per_node) {
        Ok(()) => println!("Simulation exited successfully"),
        Err(e) => println!("Simulation exited with error: {}", e),
    }
}

fn simulation(num_nodes: usize, validators_per_node: usize) -> Result<(), String> {
    if num_nodes < 1 {
        return Err("Must have at least one node".into());
    }

    let mut env = EnvironmentBuilder::minimal()
        .async_logger("debug")?
        .multi_threaded_tokio_runtime()?
        .build()?;

    let mut base_config = testing_client_config();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("should get system time")
        .as_secs();
    base_config.genesis = ClientGenesis::Interop {
        genesis_time: now,
        validator_count: num_nodes * validators_per_node,
    };

    let boot_node =
        BeaconNode::production(env.service_context("boot_node".into()), base_config.clone());

    let mut nodes = (1..num_nodes)
        .map(|i| {
            let context = env.service_context(format!("node_{}", i));
            new_with_bootnode_via_enr(context, &boot_node, base_config.clone())
        })
        .collect::<Vec<_>>();

    let _validators = nodes
        .iter()
        .enumerate()
        .map(|(i, node)| {
            let mut context = env.service_context(format!("validator_{}", i));

            // Pull the spec from the beacon node's beacon chain, in case there were some changes
            // to the spec after the node booted.
            context.eth2_config.spec = node
                .client
                .beacon_chain()
                .expect("should have beacon chain")
                .spec
                .clone();

            let context = env.service_context(format!("validator_{}", i));

            let indices =
                (i * validators_per_node..(i + 1) * validators_per_node).collect::<Vec<_>>();
            new_validator_client(
                &mut env,
                context,
                node,
                ValidatorConfig::default(),
                &indices,
            )
        })
        .collect::<Vec<_>>();

    nodes.insert(0, boot_node);

    env.block_until_ctrl_c()?;

    Ok(())
}

// TODO: this function does not result in nodes connecting to each other. This is a bug due to
// using a 0 port for discovery. Age is fixing it.
fn new_with_bootnode_via_enr<E: EthSpec>(
    context: RuntimeContext<E>,
    boot_node: &BeaconNode<E>,
    base_config: ClientConfig,
) -> BeaconNode<E> {
    let mut config = base_config;
    config.network.boot_nodes.push(
        boot_node
            .client
            .enr()
            .expect("bootnode must have a network"),
    );

    BeaconNode::production(context, config)
}

// Note: this function will block until the validator can connect to the beaco node. It is
// recommended to ensure that the beacon node is running first.
fn new_validator_client<E: EthSpec>(
    env: &mut Environment<E>,
    context: RuntimeContext<E>,
    beacon_node: &BeaconNode<E>,
    base_config: ValidatorConfig,
    keypair_indices: &[usize],
) -> LocalValidatorClient<E> {
    let mut config = base_config;

    let socket_addr = beacon_node
        .client
        .http_listen_addr()
        .expect("Must have http started");

    config.http_server = format!("http://{}:{}", socket_addr.ip(), socket_addr.port());

    env.runtime()
        .block_on(LocalValidatorClient::production_with_insecure_keypairs(
            context,
            config,
            keypair_indices,
        ))
        .expect("should start validator")
}
