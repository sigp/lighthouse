mod checks;
mod local_network;

use eth1_test_rig::GanacheEth1Instance;
use futures::{stream, Future, Stream};
use local_network::LocalNetwork;
use node_test_rig::{
    environment::EnvironmentBuilder, testing_client_config, ClientGenesis, LocalBeaconNode,
    LocalValidatorClient, ProductionClient, ValidatorConfig,
};
use std::time::{Duration, Instant};
use tokio::timer::Interval;
use types::MinimalEthSpec;

pub type E = MinimalEthSpec;
pub type BeaconNode<E> = LocalBeaconNode<ProductionClient<E>>;
pub type ValidatorClient<E> = LocalValidatorClient<E>;

fn main() {
    let nodes = 4;
    let validators_per_node = 20;

    match async_sim(nodes, validators_per_node, 4) {
        Ok(()) => println!("Simulation exited successfully"),
        Err(e) => eprintln!("Simulation exited with error: {}", e),
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

    let eth1_block_time = Duration::from_millis(15_000 / speed_up_factor);

    let spec = &mut env.eth2_config.spec;

    spec.milliseconds_per_slot = spec.milliseconds_per_slot / speed_up_factor;
    spec.eth1_follow_distance = 16;
    spec.seconds_per_day = eth1_block_time.as_secs() * spec.eth1_follow_distance * 2;
    spec.min_genesis_time = 0;
    spec.min_genesis_active_validator_count = 64;

    let slot_duration = Duration::from_millis(spec.milliseconds_per_slot);
    let validator_count = validators_per_node * node_count;
    let deposit_amount = env.eth2_config.spec.max_effective_balance;

    let context = env.core_context();
    let executor = context.executor.clone();

    let future = GanacheEth1Instance::new()
        .map(move |ganache_eth1_instance| {
            let deposit_contract = ganache_eth1_instance.deposit_contract;
            let ganache = ganache_eth1_instance.ganache;
            let eth1_endpoint = ganache.endpoint();
            let deposit_contract_address = deposit_contract.address();

            // Start a timer that produces eth1 blocks on an interval.
            executor.spawn(
                Interval::new(Instant::now(), eth1_block_time)
                    .map_err(|_| eprintln!("Eth1 block timer failed"))
                    .for_each(move |_| ganache.evm_mine().map_err(|_| ()))
                    .map_err(|_| eprintln!("Eth1 evm_mine failed"))
                    .map(|_| ()),
            );

            // Submit deposits to the deposit contract.
            executor.spawn(
                stream::unfold(0..validator_count, move |mut iter| {
                    iter.next().map(|i| {
                        println!("Submitting deposit for validator {}...", i);
                        deposit_contract
                            .deposit_deterministic_async::<E>(i, deposit_amount)
                            .map(|_| ((), iter))
                    })
                })
                .collect()
                .map(|_| ())
                .map_err(|e| eprintln!("Error submitting deposit: {}", e)),
            );

            (deposit_contract_address, eth1_endpoint)
        })
        .map(move |(deposit_contract_address, eth1_endpoint)| {
            let mut beacon_config = testing_client_config();

            beacon_config.genesis = ClientGenesis::DepositContract;
            beacon_config.eth1.endpoint = eth1_endpoint;
            beacon_config.eth1.deposit_contract_address = deposit_contract_address;
            beacon_config.eth1.deposit_contract_deploy_block = 0;
            beacon_config.eth1.lowest_cached_block_number = 0;
            beacon_config.eth1.follow_distance = 1;
            beacon_config.dummy_eth1_backend = false;
            beacon_config.sync_eth1_chain = true;

            beacon_config
        })
        .and_then(move |beacon_config| {
            LocalNetwork::new(context, beacon_config.clone())
                .map(|network| (network, beacon_config))
        })
        .and_then(move |(network, beacon_config)| {
            let network_1 = network.clone();

            stream::unfold(0..node_count - 1, move |mut iter| {
                iter.next().map(|_| {
                    network_1
                        .add_beacon_node(beacon_config.clone())
                        .map(|()| ((), iter))
                })
            })
            .collect()
            .map(|_| network)
        })
        .and_then(move |network| {
            let network_1 = network.clone();

            stream::unfold(0..node_count, move |mut iter| {
                iter.next().map(|i| {
                    let indices = (i * validators_per_node..(i + 1) * validators_per_node)
                        .collect::<Vec<_>>();

                    network_1
                        .add_validator_client(ValidatorConfig::default(), i, indices)
                        .map(|()| ((), iter))
                })
            })
            .collect()
            .map(|_| network)
        })
        .and_then(move |network| {
            checks::verify_first_finalization(network.clone(), slot_duration)
                .join(checks::verify_validator_onboarding(
                    network.clone(),
                    slot_duration,
                    validator_count,
                ))
                .map(|_| network)
        })
        .map(|network| {
            println!(
                "Simulation complete. Finished with {} beacon nodes and {} validator clients",
                network.beacon_node_count(),
                network.validator_client_count()
            );

            // Be explicit about dropping the network, as this kills all the nodes. This ensures
            // all the checks have adequate time to pass.
            drop(network)
        });

    env.runtime().block_on(future)
}
