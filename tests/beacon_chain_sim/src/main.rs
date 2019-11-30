mod checks;
mod local_network;

use futures::{future, stream, Future, Stream};
use local_network::LocalNetwork;
use node_test_rig::{
    environment::EnvironmentBuilder, testing_client_config, ClientGenesis, LocalBeaconNode,
    LocalValidatorClient, ProductionClient, ValidatorConfig,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use types::MinimalEthSpec;

pub type E = MinimalEthSpec;
pub type BeaconNode<E> = LocalBeaconNode<ProductionClient<E>>;
pub type ValidatorClient<E> = LocalValidatorClient<E>;

fn main() {
    let nodes = 4;
    let validators_per_node = 64 / nodes;

    match async_sim(nodes, validators_per_node, 4) {
        Ok(()) => println!("Simulation exited successfully"),
        Err(e) => println!("Simulation exited with error: {}", e),
    }
}

fn async_sim(
    node_count: usize,
    validators_per_node: usize,
    speed_up_factor: u64,
) -> Result<(), String> {
    let mut env = EnvironmentBuilder::minimal()
        .async_logger("debug")?
        .multi_threaded_tokio_runtime()?
        .build()?;

    env.eth2_config.spec.milliseconds_per_slot =
        env.eth2_config.spec.milliseconds_per_slot / speed_up_factor;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("should get system time")
        .as_secs();

    let mut beacon_config = testing_client_config();
    beacon_config.genesis = ClientGenesis::Interop {
        genesis_time: now,
        validator_count: node_count * validators_per_node,
    };

    let slot_duration = Duration::from_millis(env.eth2_config.spec.milliseconds_per_slot);

    let network = LocalNetwork::new(env.core_context(), beacon_config.clone())?;

    let network_1 = network.clone();
    let network_2 = network.clone();
    let network_3 = network.clone();

    let future = future::ok(())
        .and_then(move |()| {
            let network = network_1;

            for _ in 0..node_count - 1 {
                network.add_beacon_node(beacon_config.clone())?;
            }

            Ok(())
        })
        .and_then(move |()| {
            let network = network_2;

            stream::unfold(0..node_count, move |mut iter| {
                iter.next().map(|i| {
                    let indices = (i * validators_per_node..(i + 1) * validators_per_node)
                        .collect::<Vec<_>>();

                    network
                        .add_validator_client(ValidatorConfig::default(), i, indices)
                        .map(|()| ((), iter))
                })
            })
            .collect()
            .map(|_| ())
        })
        .and_then(move |_| {
            let network = network_3;

            checks::verify_first_finalization(network, slot_duration)
        });

    env.runtime().block_on(future)
}
