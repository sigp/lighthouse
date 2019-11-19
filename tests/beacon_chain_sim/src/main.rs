use node_test_rig::{
    environment::{EnvironmentBuilder, RuntimeContext},
    testing_client_config, ClientConfig, LocalBeaconNode, ProductionClient,
};
use types::EthSpec;

pub type BeaconNode<E> = LocalBeaconNode<ProductionClient<E>>;

fn main() {
    match simulation(4) {
        Ok(()) => println!("Simulation exited successfully"),
        Err(e) => println!("Simulation exited with error: {}", e),
    }
}

fn simulation(num_nodes: usize) -> Result<(), String> {
    if num_nodes < 1 {
        return Err("Must have at least one node".into());
    }

    let mut env = EnvironmentBuilder::minimal()
        .async_logger("debug")?
        .multi_threaded_tokio_runtime()?
        .build()?;

    let base_config = testing_client_config();

    let boot_node =
        BeaconNode::production(env.service_context("boot_node".into()), base_config.clone());

    let nodes = (1..num_nodes)
        .map(|i| {
            let context = env.service_context(format!("node_{}", i));
            new_with_bootnode_via_enr(context, &boot_node, base_config.clone())
        })
        .collect::<Vec<_>>();

    env.block_until_ctrl_c()?;

    Ok(())
}

// TODO: this function does not result in nodes connecting to each other. Age to investigate?
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

fn new_with_bootnode_via_multiaddr<E: EthSpec>(
    context: RuntimeContext<E>,
    boot_node: &BeaconNode<E>,
    base_config: ClientConfig,
) -> BeaconNode<E> {
    let mut config = base_config;
    config.network.libp2p_nodes.push(
        boot_node
            .client
            .libp2p_listen_addresses()
            .expect("bootnode must have a network")
            .first()
            .expect("bootnode must have at least one listen addr")
            .clone(),
    );

    BeaconNode::production(context, config)
}
