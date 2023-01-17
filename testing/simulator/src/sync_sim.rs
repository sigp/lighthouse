use crate::checks::{epoch_delay, verify_all_finalized_at};
use crate::local_network::LocalNetwork;
use clap::ArgMatches;
use futures::prelude::*;
use node_test_rig::{
    environment::{EnvironmentBuilder, LoggerConfig},
    testing_client_config, ClientGenesis, ValidatorFiles,
};
use node_test_rig::{testing_validator_config, ClientConfig};
use std::cmp::max;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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
        .initialize_logger(LoggerConfig {
            path: None,
            debug_level: String::from(log_level),
            logfile_debug_level: String::from("debug"),
            log_format: log_format.map(String::from),
            logfile_format: None,
            log_color: false,
            disable_log_timestamp: false,
            max_log_size: 0,
            max_log_number: 0,
            compression: false,
            is_restricted: true,
        })?
        .multi_threaded_tokio_runtime()?
        .build()?;

    let spec = &mut env.eth2_config.spec;
    let end_after_checks = true;
    let eth1_block_time = Duration::from_millis(15_000 / speed_up_factor);

    // Set fork epochs to test syncing across fork boundaries
    spec.altair_fork_epoch = Some(Epoch::new(1));
    spec.bellatrix_fork_epoch = Some(Epoch::new(2));
    spec.seconds_per_slot /= speed_up_factor;
    spec.seconds_per_slot = max(1, spec.seconds_per_slot);
    spec.eth1_follow_distance = 16;
    spec.genesis_delay = eth1_block_time.as_secs() * spec.eth1_follow_distance * 2;
    spec.min_genesis_time = 0;
    spec.min_genesis_active_validator_count = 64;
    spec.seconds_per_eth1_block = 1;

    let num_validators = 8;
    let slot_duration = Duration::from_secs(spec.seconds_per_slot);
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

    beacon_config.http_api.allow_sync_stalled = true;

    beacon_config.network.enr_address = Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

    // Generate the directories and keystores required for the validator clients.
    let validator_indices = (0..num_validators).collect::<Vec<_>>();
    let validator_files = ValidatorFiles::with_keystores(&validator_indices).unwrap();

    let main_future = async {
        /*
         * Create a new `LocalNetwork` with one beacon node.
         */
        let network = LocalNetwork::new(context, beacon_config.clone()).await?;

        /*
         * Add a validator client which handles all validators from the genesis state.
         */
        network
            .add_validator_client(testing_validator_config(), 0, validator_files, true)
            .await?;

        // Check all syncing strategies one after other.
        pick_strategy(
            &strategy,
            network.clone(),
            beacon_config.clone(),
            slot_duration,
            initial_delay,
            sync_timeout,
        )
        .await?;

        // The `final_future` either completes immediately or never completes, depending on the value
        // of `end_after_checks`.

        if !end_after_checks {
            future::pending::<()>().await;
        }

        /*
         * End the simulation by dropping the network. This will kill all running beacon nodes and
         * validator clients.
         */
        println!(
            "Simulation complete. Finished with {} beacon nodes and {} validator clients",
            network.beacon_node_count(),
            network.validator_client_count()
        );

        // Be explicit about dropping the network, as this kills all the nodes. This ensures
        // all the checks have adequate time to pass.
        drop(network);
        Ok::<(), String>(())
    };

    env.runtime().block_on(main_future).unwrap();

    env.fire_signal();
    env.shutdown_on_idle();

    Ok(())
}

pub async fn pick_strategy<E: EthSpec>(
    strategy: &str,
    network: LocalNetwork<E>,
    beacon_config: ClientConfig,
    slot_duration: Duration,
    initial_delay: u64,
    sync_timeout: u64,
) -> Result<(), String> {
    match strategy {
        "one-node" => {
            verify_one_node_sync(
                network,
                beacon_config,
                slot_duration,
                initial_delay,
                sync_timeout,
            )
            .await
        }
        "two-nodes" => {
            verify_two_nodes_sync(
                network,
                beacon_config,
                slot_duration,
                initial_delay,
                sync_timeout,
            )
            .await
        }
        "mixed" => {
            verify_in_between_sync(
                network,
                beacon_config,
                slot_duration,
                initial_delay,
                sync_timeout,
            )
            .await
        }
        "all" => {
            verify_syncing(
                network,
                beacon_config,
                slot_duration,
                initial_delay,
                sync_timeout,
            )
            .await
        }
        _ => Err("Invalid strategy".into()),
    }
}

/// Verify one node added after `initial_delay` epochs is in sync
/// after `sync_timeout` epochs.
pub async fn verify_one_node_sync<E: EthSpec>(
    network: LocalNetwork<E>,
    beacon_config: ClientConfig,
    slot_duration: Duration,
    initial_delay: u64,
    sync_timeout: u64,
) -> Result<(), String> {
    let epoch_duration = slot_duration * (E::slots_per_epoch() as u32);
    let network_c = network.clone();
    // Delay for `initial_delay` epochs before adding another node to start syncing
    epoch_delay(
        Epoch::new(initial_delay),
        slot_duration,
        E::slots_per_epoch(),
    )
    .await;
    // Add a beacon node
    network.add_beacon_node(beacon_config).await?;
    // Check every `epoch_duration` if nodes are synced
    // limited to at most `sync_timeout` epochs
    let mut interval = tokio::time::interval(epoch_duration);
    let mut count = 0;
    loop {
        interval.tick().await;
        if count >= sync_timeout || !check_still_syncing(&network_c).await? {
            break;
        }
        count += 1;
    }
    let epoch = network.bootnode_epoch().await?;
    verify_all_finalized_at(network, epoch)
        .map_err(|e| format!("One node sync error: {}", e))
        .await
}

/// Verify two nodes added after `initial_delay` epochs are in sync
/// after `sync_timeout` epochs.
pub async fn verify_two_nodes_sync<E: EthSpec>(
    network: LocalNetwork<E>,
    beacon_config: ClientConfig,
    slot_duration: Duration,
    initial_delay: u64,
    sync_timeout: u64,
) -> Result<(), String> {
    let epoch_duration = slot_duration * (E::slots_per_epoch() as u32);
    let network_c = network.clone();
    // Delay for `initial_delay` epochs before adding another node to start syncing
    epoch_delay(
        Epoch::new(initial_delay),
        slot_duration,
        E::slots_per_epoch(),
    )
    .await;
    // Add beacon nodes
    network.add_beacon_node(beacon_config.clone()).await?;
    network.add_beacon_node(beacon_config).await?;
    // Check every `epoch_duration` if nodes are synced
    // limited to at most `sync_timeout` epochs
    let mut interval = tokio::time::interval(epoch_duration);
    let mut count = 0;
    loop {
        interval.tick().await;
        if count >= sync_timeout || !check_still_syncing(&network_c).await? {
            break;
        }
        count += 1;
    }
    let epoch = network.bootnode_epoch().await?;
    verify_all_finalized_at(network, epoch)
        .map_err(|e| format!("One node sync error: {}", e))
        .await
}

/// Add 2 syncing nodes after `initial_delay` epochs,
/// Add another node after `sync_timeout - 5` epochs and verify all are
/// in sync after `sync_timeout + 5` epochs.
pub async fn verify_in_between_sync<E: EthSpec>(
    network: LocalNetwork<E>,
    beacon_config: ClientConfig,
    slot_duration: Duration,
    initial_delay: u64,
    sync_timeout: u64,
) -> Result<(), String> {
    let epoch_duration = slot_duration * (E::slots_per_epoch() as u32);
    let network_c = network.clone();
    // Delay for `initial_delay` epochs before adding another node to start syncing
    let config1 = beacon_config.clone();
    epoch_delay(
        Epoch::new(initial_delay),
        slot_duration,
        E::slots_per_epoch(),
    )
    .await;
    // Add two beacon nodes
    network.add_beacon_node(beacon_config.clone()).await?;
    network.add_beacon_node(beacon_config).await?;
    // Delay before adding additional syncing nodes.
    epoch_delay(
        Epoch::new(sync_timeout - 5),
        slot_duration,
        E::slots_per_epoch(),
    )
    .await;
    // Add a beacon node
    network.add_beacon_node(config1.clone()).await?;
    // Check every `epoch_duration` if nodes are synced
    // limited to at most `sync_timeout` epochs
    let mut interval = tokio::time::interval(epoch_duration);
    let mut count = 0;
    loop {
        interval.tick().await;
        if count >= sync_timeout || !check_still_syncing(&network_c).await? {
            break;
        }
        count += 1;
    }
    let epoch = network.bootnode_epoch().await?;
    verify_all_finalized_at(network, epoch)
        .map_err(|e| format!("One node sync error: {}", e))
        .await
}

/// Run syncing strategies one after other.
pub async fn verify_syncing<E: EthSpec>(
    network: LocalNetwork<E>,
    beacon_config: ClientConfig,
    slot_duration: Duration,
    initial_delay: u64,
    sync_timeout: u64,
) -> Result<(), String> {
    verify_one_node_sync(
        network.clone(),
        beacon_config.clone(),
        slot_duration,
        initial_delay,
        sync_timeout,
    )
    .await?;
    println!("Completed one node sync");
    verify_two_nodes_sync(
        network.clone(),
        beacon_config.clone(),
        slot_duration,
        initial_delay,
        sync_timeout,
    )
    .await?;
    println!("Completed two node sync");
    verify_in_between_sync(
        network,
        beacon_config,
        slot_duration,
        initial_delay,
        sync_timeout,
    )
    .await?;
    println!("Completed in between sync");
    Ok(())
}

pub async fn check_still_syncing<E: EthSpec>(network: &LocalNetwork<E>) -> Result<bool, String> {
    // get syncing status of nodes
    let mut status = Vec::new();
    for remote_node in network.remote_nodes()? {
        status.push(
            remote_node
                .get_node_syncing()
                .await
                .map(|body| body.data.is_syncing)
                .map_err(|e| format!("Get syncing status via http failed: {:?}", e))?,
        )
    }
    Ok(status.iter().any(|is_syncing| *is_syncing))
}
