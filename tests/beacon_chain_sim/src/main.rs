//! This crate provides a simluation that creates `n` beacon node and validator clients, each with
//! `v` validators. A deposit contract is deployed at the start of the simulation using a local
//! `ganache-cli` instance (you must have `ganache-cli` installed and avaliable on your path). All
//! beacon nodes independently listen for genesis from the deposit contract, then start operating.
//!
//! As the simulation runs, there are checks made to ensure that all components are running
//! correctly. If any of these checks fail, the simulation will exit immediately.
//!
//! By default, the simulation will end as soon as all checks have finished. It may be configured
//! to run indefinitely by setting `end_after_checks = false`.
//!
//! ## Future works
//!
//! Presently all the beacon nodes and validator clients all log to stdout. Additionally, the
//! simulation uses `println` to communicate some info. It might be nice if the nodes logged to
//! easy-to-find files and stdout only contained info from the simulation.
//!
//! It would also be nice to add a CLI using `clap` so that the variables in `main()` can be
//! changed without a recompile.

mod checks;
mod local_network;

use env_logger::{Builder, Env};
use eth1_test_rig::GanacheEth1Instance;
use futures::{future, stream, Future, Stream};
use local_network::LocalNetwork;
use node_test_rig::{
    environment::EnvironmentBuilder, testing_client_config, ClientGenesis, ValidatorConfig,
};
use std::time::{Duration, Instant};
use tokio::timer::Interval;
use types::MinimalEthSpec;

pub type E = MinimalEthSpec;

fn main() {
    // Debugging output for libp2p and external crates.
    Builder::from_env(Env::default()).init();

    let nodes = 4;
    let validators_per_node = 20;
    let log_level = "debug";
    let log_format = None;
    let speed_up_factor = 4;
    let end_after_checks = true;

    match async_sim(
        nodes,
        validators_per_node,
        speed_up_factor,
        log_level,
        log_format,
        end_after_checks,
    ) {
        Ok(()) => println!("Simulation exited successfully"),
        Err(e) => {
            eprintln!("Simulation exited with error: {}", e);
            std::process::exit(1)
        }
    }
}

fn async_sim(
    node_count: usize,
    validators_per_node: usize,
    speed_up_factor: u64,
    log_level: &str,
    log_format: Option<&str>,
    end_after_checks: bool,
) -> Result<(), String> {
    let mut env = EnvironmentBuilder::minimal()
        .async_logger(log_level, log_format)?
        .multi_threaded_tokio_runtime()?
        .build()?;

    let eth1_block_time = Duration::from_millis(15_000 / speed_up_factor);

    let spec = &mut env.eth2_config.spec;

    spec.milliseconds_per_slot /= speed_up_factor;
    spec.eth1_follow_distance = 16;
    spec.seconds_per_day = eth1_block_time.as_secs() * spec.eth1_follow_distance * 2;
    spec.min_genesis_time = 0;
    spec.min_genesis_active_validator_count = 64;

    let slot_duration = Duration::from_millis(spec.milliseconds_per_slot);
    let initial_validator_count = spec.min_genesis_active_validator_count as usize;
    let total_validator_count = validators_per_node * node_count;
    let deposit_amount = env.eth2_config.spec.max_effective_balance;

    let context = env.core_context();
    let executor = context.executor.clone();

    let future = GanacheEth1Instance::new()
        /*
         * Deploy the deposit contract, spawn tasks to keep creating new blocks and deposit
         * validators.
         */
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
                stream::unfold(0..total_validator_count, move |mut iter| {
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
        /*
         * Create a new `LocalNetwork` with one beacon node.
         */
        .and_then(move |beacon_config| {
            LocalNetwork::new(context, beacon_config.clone())
                .map(|network| (network, beacon_config))
        })
        /*
         * One by one, add beacon nodes to the network.
         */
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
        /*
         * One by one, add validator clients to the network. Each validator client is attached to
         * a single corresponding beacon node.
         */
        .and_then(move |network| {
            let network_1 = network.clone();

            // Note: presently the validator client future will only resolve once genesis time
            // occurs. This is great for this scenario, but likely to change in the future.
            //
            // If the validator client future behaviour changes, we would need to add a new future
            // that delays until genesis. Otherwise, all of the checks that start in the next
            // future will start too early.

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
        /*
         * Start the processes that will run checks on the network as it runs.
         */
        .and_then(move |network| {
            // The `final_future` either completes immediately or never completes, depending on the value
            // of `end_after_checks`.
            let final_future: Box<dyn Future<Item = (), Error = String> + Send> =
                if end_after_checks {
                    Box::new(future::ok(()).map_err(|()| "".to_string()))
                } else {
                    Box::new(future::empty().map_err(|()| "".to_string()))
                };

            future::ok(())
                // Check that the chain finalizes at the first given opportunity.
                .join(checks::verify_first_finalization(
                    network.clone(),
                    slot_duration,
                ))
                // Check that the chain starts with the expected validator count.
                .join(checks::verify_initial_validator_count(
                    network.clone(),
                    slot_duration,
                    initial_validator_count,
                ))
                // Check that validators greater than `spec.min_genesis_active_validator_count` are
                // onboarded at the first possible opportunity.
                .join(checks::verify_validator_onboarding(
                    network.clone(),
                    slot_duration,
                    total_validator_count,
                ))
                // End now or run forever, depending on the `end_after_checks` flag.
                .join(final_future)
                .map(|_| network)
        })
        /*
         * End the simulation by dropping the network. This will kill all running beacon nodes and
         * validator clients.
         */
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
