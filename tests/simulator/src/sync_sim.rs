use crate::checks::{epoch_delay, verify_all_finalized_at};
use crate::local_network::LocalNetwork;
use clap::ArgMatches;
use futures::{future, stream, Future, IntoFuture, Stream};
use node_test_rig::ClientConfig;
use node_test_rig::{
    environment::EnvironmentBuilder, testing_client_config, ClientGenesis, ValidatorConfig,
};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::timer::Interval;
use types::{Epoch, EthSpec};

pub fn run_syncing_sim(matches: &ArgMatches) -> Result<(), String> {
    let initial_delay = value_t!(matches, "initial_delay", u64).unwrap();
    let sync_timeout = value_t!(matches, "sync_timeout", u64).unwrap();
    let speed_up_factor = value_t!(matches, "speedup", u64).unwrap();
    let strategy = value_t!(matches, "strategy", String).unwrap();

    println!("Syncing Simulator:");
    println!(" initial_delay:{}", initial_delay);
    println!(" sync timeout: {}", sync_timeout);
    println!(" speed up factor:{}", speed_up_factor);
    println!(" strategy:{}", strategy);

    let log_level = "debug";
    let log_format = None;

    syncing_sim(
        speed_up_factor,
        initial_delay,
        sync_timeout,
        strategy,
        log_level,
        log_format,
    )
}

fn syncing_sim(
    speed_up_factor: u64,
    initial_delay: u64,
    sync_timeout: u64,
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
    let eth1_block_time = Duration::from_millis(15_000 / speed_up_factor);

    spec.milliseconds_per_slot /= speed_up_factor;
    spec.eth1_follow_distance = 16;
    spec.min_genesis_delay = eth1_block_time.as_secs() * spec.eth1_follow_distance * 2;
    spec.min_genesis_time = 0;
    spec.min_genesis_active_validator_count = 64;
    spec.seconds_per_eth1_block = 1;

    let num_validators = 8;
    let slot_duration = Duration::from_millis(spec.milliseconds_per_slot);
    let context = env.core_context();
    let mut beacon_config = testing_client_config();

    let genesis_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "should get system time")?
        + Duration::from_secs(5);
    beacon_config.genesis = ClientGenesis::Interop {
        validator_count: num_validators,
        genesis_time: genesis_time.as_secs(),
    };
    beacon_config.dummy_eth1_backend = true;
    beacon_config.sync_eth1_chain = true;

    beacon_config.network.enr_address = Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

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
                    sync_timeout,
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
    sync_timeout: u64,
) -> Box<dyn Future<Item = (), Error = String> + Send + 'static> {
    match strategy {
        "one-node" => Box::new(verify_one_node_sync(
            network,
            beacon_config,
            slot_duration,
            initial_delay,
            sync_timeout,
        )),
        "two-nodes" => Box::new(verify_two_nodes_sync(
            network,
            beacon_config,
            slot_duration,
            initial_delay,
            sync_timeout,
        )),
        "mixed" => Box::new(verify_in_between_sync(
            network,
            beacon_config,
            slot_duration,
            initial_delay,
            sync_timeout,
        )),
        "all" => Box::new(verify_syncing(
            network,
            beacon_config,
            slot_duration,
            initial_delay,
            sync_timeout,
        )),
        _ => Box::new(Err("Invalid strategy".into()).into_future()),
    }
}

/// Verify one node added after `initial_delay` epochs is in sync
/// after `sync_timeout` epochs.
pub fn verify_one_node_sync<E: EthSpec>(
    network: LocalNetwork<E>,
    beacon_config: ClientConfig,
    slot_duration: Duration,
    initial_delay: u64,
    sync_timeout: u64,
) -> impl Future<Item = (), Error = String> {
    let epoch_duration = slot_duration * (E::slots_per_epoch() as u32);
    let network_c = network.clone();
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
        // Check every `epoch_duration` if nodes are synced
        // limited to at most `sync_timeout` epochs
        Interval::new_interval(epoch_duration)
            .take(sync_timeout)
            .map_err(|_| "Failed to create interval".to_string())
            .take_while(move |_| check_still_syncing(&network_c))
            .for_each(|_| Ok(())) // consume the stream
            .map(|_| network)
    })
    .and_then(move |network| network.bootnode_epoch().map(|e| (e, network)))
    .and_then(move |(epoch, network)| {
        verify_all_finalized_at(network, epoch).map_err(|e| format!("One node sync error: {}", e))
    })
}

/// Verify two nodes added after `initial_delay` epochs are in sync
/// after `sync_timeout` epochs.
pub fn verify_two_nodes_sync<E: EthSpec>(
    network: LocalNetwork<E>,
    beacon_config: ClientConfig,
    slot_duration: Duration,
    initial_delay: u64,
    sync_timeout: u64,
) -> impl Future<Item = (), Error = String> {
    let epoch_duration = slot_duration * (E::slots_per_epoch() as u32);
    let network_c = network.clone();
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
            .map(|_| (network, beacon_config))
            .and_then(|(network, beacon_config)| {
                network.add_beacon_node(beacon_config).map(|_| network)
            })
    })
    .and_then(move |network| {
        // Check every `epoch_duration` if nodes are synced
        // limited to at most `sync_timeout` epochs
        Interval::new_interval(epoch_duration)
            .take(sync_timeout)
            .map_err(|_| "Failed to create interval".to_string())
            .take_while(move |_| check_still_syncing(&network_c))
            .for_each(|_| Ok(())) // consume the stream
            .map(|_| network)
    })
    .and_then(move |network| network.bootnode_epoch().map(|e| (e, network)))
    .and_then(move |(epoch, network)| {
        verify_all_finalized_at(network, epoch).map_err(|e| format!("Two node sync error: {}", e))
    })
}

/// Add 2 syncing nodes after `initial_delay` epochs,
/// Add another node after `sync_timeout - 5` epochs and verify all are
/// in sync after `sync_timeout + 5` epochs.
pub fn verify_in_between_sync<E: EthSpec>(
    network: LocalNetwork<E>,
    beacon_config: ClientConfig,
    slot_duration: Duration,
    initial_delay: u64,
    sync_timeout: u64,
) -> impl Future<Item = (), Error = String> {
    let epoch_duration = slot_duration * (E::slots_per_epoch() as u32);
    let network_c = network.clone();
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
            .map(|_| (network, beacon_config))
            .and_then(|(network, beacon_config)| {
                network.add_beacon_node(beacon_config).map(|_| network)
            })
    })
    .and_then(move |network| {
        // Delay before adding additional syncing nodes.
        epoch_delay(
            Epoch::new(sync_timeout - 5),
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
        // Check every `epoch_duration` if nodes are synced
        // limited to at most `sync_timeout` epochs
        Interval::new_interval(epoch_duration)
            .take(sync_timeout + 5)
            .map_err(|_| "Failed to create interval".to_string())
            .take_while(move |_| check_still_syncing(&network_c))
            .for_each(|_| Ok(())) // consume the stream
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
    sync_timeout: u64,
) -> impl Future<Item = (), Error = String> {
    verify_one_node_sync(
        network.clone(),
        beacon_config.clone(),
        slot_duration,
        initial_delay,
        sync_timeout,
    )
    .map(|_| println!("Completed one node sync"))
    .and_then(move |_| {
        verify_two_nodes_sync(
            network.clone(),
            beacon_config.clone(),
            slot_duration,
            initial_delay,
            sync_timeout,
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
            sync_timeout,
        )
        .map(|_| println!("Completed in between sync"))
    })
}

pub fn check_still_syncing<E: EthSpec>(
    network: &LocalNetwork<E>,
) -> impl Future<Item = bool, Error = String> {
    network
        .remote_nodes()
        .into_future()
        // get syncing status of nodes
        .and_then(|remote_nodes| {
            stream::unfold(remote_nodes.into_iter(), |mut iter| {
                iter.next().map(|remote_node| {
                    remote_node
                        .http
                        .node()
                        .syncing_status()
                        .map(|status| status.is_syncing)
                        .map(|status| (status, iter))
                        .map_err(|e| format!("Get syncing status via http failed: {:?}", e))
                })
            })
            .collect()
        })
        .and_then(move |status| Ok(status.iter().any(|is_syncing| *is_syncing)))
        .map_err(|e| format!("Failed syncing check: {:?}", e))
}
