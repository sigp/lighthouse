use crate::checks::{epoch_delay, verify_all_finalized_at};
use crate::local_network::LocalNetwork;
use clap::ArgMatches;
use futures::{future, Future, IntoFuture};
use node_test_rig::ClientConfig;
use node_test_rig::{environment::EnvironmentBuilder, testing_client_config, ValidatorConfig};
use std::time::Duration;
use types::{Epoch, EthSpec};

pub fn run_syncing_sim(matches: &ArgMatches) -> Result<(), String> {
    let initial_delay = value_t!(matches, "initial_delay", u64).unwrap_or(50);
    let sync_delay = value_t!(matches, "sync_delay", u64).unwrap_or(10);
    let speed_up_factor = value_t!(matches, "speedup", u64).unwrap_or(15);
    let strategy = value_t!(matches, "strategy", String).unwrap_or("all".into());

    println!("Syncing Simulator:");
    println!(" initial_delay:{}", initial_delay);
    println!(" sync delay:{}", sync_delay);
    println!(" speed up factor:{}", speed_up_factor);
    println!(" strategy:{}", strategy);

    let log_level = "debug";
    let log_format = None;

    syncing_sim(
        speed_up_factor,
        initial_delay,
        sync_delay,
        strategy,
        log_level,
        log_format,
    )
}

fn syncing_sim(
    speed_up_factor: u64,
    initial_delay: u64,
    sync_delay: u64,
    strategy: String,
    log_level: &str,
    log_format: Option<&str>,
) -> Result<(), String> {
    let mut env = EnvironmentBuilder::minimal()
        .async_logger(log_level, log_format)?
        .multi_threaded_tokio_runtime()?
        .build()?;

    let spec = &mut env.eth2_config.spec;
    let end_after_checks = true;

    spec.milliseconds_per_slot = spec.milliseconds_per_slot / speed_up_factor;
    spec.min_genesis_time = 0;
    spec.min_genesis_active_validator_count = 16;

    let slot_duration = Duration::from_millis(spec.milliseconds_per_slot);
    let context = env.core_context();
    let num_validators = 8;
    let beacon_config = testing_client_config();

    let future = LocalNetwork::new(context, beacon_config.clone())
        /*
         * Add a validator client which handles all validators from the genesis state.
         */
        .and_then(move |network| {
            network
                .add_validator_client(ValidatorConfig::default(), 0, (0..num_validators).collect())
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
                // Check all syncing strategies one after other.
                .join(pick_strategy(
                    &strategy,
                    network.clone(),
                    beacon_config.clone(),
                    slot_duration,
                    initial_delay,
                    sync_delay,
                ))
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

pub fn pick_strategy<E: EthSpec>(
    strategy: &str,
    network: LocalNetwork<E>,
    beacon_config: ClientConfig,
    slot_duration: Duration,
    initial_delay: u64,
    sync_delay: u64,
) -> Box<dyn Future<Item = (), Error = String> + Send + 'static> {
    match strategy {
        "one-node" => Box::new(verify_one_node_sync(
            network,
            beacon_config,
            slot_duration,
            initial_delay,
            sync_delay,
        )),
        "two-nodes" => Box::new(verify_two_nodes_sync(
            network,
            beacon_config,
            slot_duration,
            initial_delay,
            sync_delay,
        )),
        "mixed" => Box::new(verify_in_between_sync(
            network,
            beacon_config,
            slot_duration,
            initial_delay,
            sync_delay,
        )),
        "all" => Box::new(verify_syncing(
            network,
            beacon_config,
            slot_duration,
            initial_delay,
            sync_delay,
        )),
        _ => Box::new(Err("Invalid strategy".into()).into_future()),
    }
}

/// Verify one node added after `initial_delay` epochs is in sync
/// after `sync_delay` epochs.
pub fn verify_one_node_sync<E: EthSpec>(
    network: LocalNetwork<E>,
    beacon_config: ClientConfig,
    slot_duration: Duration,
    initial_delay: u64,
    sync_delay: u64,
) -> impl Future<Item = (), Error = String> {
    // Delay for `initial_delay` epochs before adding another node to start syncing
    epoch_delay(
        Epoch::new(initial_delay),
        slot_duration,
        E::slots_per_epoch(),
    )
    .and_then(move |_| {
        // Add a beacon node
        network.add_beacon_node(beacon_config).map(|_| network)
    })
    .and_then(move |network| {
        // Delay for `sync_delay` epochs before verifying synced state.
        epoch_delay(Epoch::new(sync_delay), slot_duration, E::slots_per_epoch()).map(|_| network)
    })
    .and_then(move |network| network.bootnode_epoch().map(|e| (e, network)))
    .and_then(move |(epoch, network)| {
        verify_all_finalized_at(network, epoch).map_err(|e| format!("One node sync error: {}", e))
    })
}

/// Verify two nodes added after `initial_delay` epochs are in sync
/// after `sync_delay` epochs.
pub fn verify_two_nodes_sync<E: EthSpec>(
    network: LocalNetwork<E>,
    beacon_config: ClientConfig,
    slot_duration: Duration,
    initial_delay: u64,
    sync_delay: u64,
) -> impl Future<Item = (), Error = String> {
    // Delay for `initial_delay` epochs before adding another node to start syncing
    epoch_delay(
        Epoch::new(initial_delay),
        slot_duration,
        E::slots_per_epoch(),
    )
    .and_then(move |_| {
        // Add beacon nodes
        network
            .add_beacon_node(beacon_config.clone())
            .join(network.add_beacon_node(beacon_config.clone()))
            .map(|_| network)
    })
    .and_then(move |network| {
        // Delay for `sync_delay` epochs before verifying synced state.
        epoch_delay(Epoch::new(sync_delay), slot_duration, E::slots_per_epoch()).map(|_| network)
    })
    .and_then(move |network| network.bootnode_epoch().map(|e| (e, network)))
    .and_then(move |(epoch, network)| {
        verify_all_finalized_at(network, epoch).map_err(|e| format!("Two node sync error: {}", e))
    })
}

/// Add 2 syncing nodes after `initial_delay` epochs,
/// Add another node after `sync_delay - 5` epochs and verify all are
/// in sync after `sync_delay + 5` epochs.
pub fn verify_in_between_sync<E: EthSpec>(
    network: LocalNetwork<E>,
    beacon_config: ClientConfig,
    slot_duration: Duration,
    initial_delay: u64,
    sync_delay: u64,
) -> impl Future<Item = (), Error = String> {
    // Delay for `initial_delay` epochs before adding another node to start syncing
    let config1 = beacon_config.clone();
    epoch_delay(
        Epoch::new(initial_delay),
        slot_duration,
        E::slots_per_epoch(),
    )
    .and_then(move |_| {
        // Add a beacon node
        network
            .add_beacon_node(beacon_config.clone())
            .join(network.add_beacon_node(beacon_config.clone()))
            .map(|_| network)
    })
    .and_then(move |network| {
        // Delay before adding additional syncing nodes.
        epoch_delay(
            Epoch::new(sync_delay - 5),
            slot_duration,
            E::slots_per_epoch(),
        )
        .map(|_| network)
    })
    .and_then(move |network| {
        // Add a beacon node
        network.add_beacon_node(config1.clone()).map(|_| network)
    })
    .and_then(move |network| {
        // Delay for `sync_delay` epochs before verifying synced state.
        epoch_delay(
            Epoch::new(sync_delay + 5),
            slot_duration,
            E::slots_per_epoch(),
        )
        .map(|_| network)
    })
    .and_then(move |network| network.bootnode_epoch().map(|e| (e, network)))
    .and_then(move |(epoch, network)| {
        verify_all_finalized_at(network, epoch).map_err(|e| format!("In between sync error: {}", e))
    })
}

/// Run syncing strategies one after other.
pub fn verify_syncing<E: EthSpec>(
    network: LocalNetwork<E>,
    beacon_config: ClientConfig,
    slot_duration: Duration,
    initial_delay: u64,
    sync_delay: u64,
) -> impl Future<Item = (), Error = String> {
    verify_one_node_sync(
        network.clone(),
        beacon_config.clone(),
        slot_duration,
        initial_delay,
        sync_delay,
    )
    .map(|_| println!("Completed one node sync"))
    .and_then(move |_| {
        verify_two_nodes_sync(
            network.clone(),
            beacon_config.clone(),
            slot_duration,
            initial_delay,
            sync_delay,
        )
        .map(|_| {
            println!("Completed two node sync");
            (network, beacon_config)
        })
    })
    .and_then(move |(network, beacon_config)| {
        verify_in_between_sync(
            network,
            beacon_config,
            slot_duration,
            initial_delay,
            sync_delay,
        )
        .map(|_| println!("Completed in between sync"))
    })
}
