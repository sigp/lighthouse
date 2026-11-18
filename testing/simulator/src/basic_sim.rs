use crate::checks::LightClientUpdateChecker;
use crate::driver::SimDriver;
use crate::local_network::LocalNetworkParams;
use crate::local_network::TERMINAL_BLOCK;
use crate::{LocalNetwork, checks};
use clap::ArgMatches;

use crate::retry::with_retry;
use node_test_rig::{
    ApiTopic, ValidatorFiles,
    environment::{EnvironmentBuilder, LoggerConfig},
    testing_validator_config,
};
use rayon::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;

use environment::tracing_common;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use logging::build_workspace_filter;
use tracing::Level;
use types::{Epoch, EthSpec, MinimalEthSpec, Slot};

const END_EPOCH: u64 = 16;
const GENESIS_DELAY: u64 = 38;
const SLOT_DURATION_MS: u64 = 60_000;
const ALTAIR_FORK_EPOCH: u64 = 0;
const BELLATRIX_FORK_EPOCH: u64 = 0;
const CAPELLA_FORK_EPOCH: u64 = 0;
const DENEB_FORK_EPOCH: u64 = 0;
const ELECTRA_FORK_EPOCH: u64 = 0;
const FULU_FORK_EPOCH: u64 = 0;
const GLOAS_FORK_EPOCH: u64 = 2;

const SUGGESTED_FEE_RECIPIENT: [u8; 20] =
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

#[allow(clippy::large_stack_frames)]
pub fn run_basic_sim(matches: &ArgMatches) -> Result<(), String> {
    let (_name, subcommand_matches) = matches.subcommand().expect("subcommand");
    let node_count = subcommand_matches
        .get_one::<String>("nodes")
        .expect("missing nodes default")
        .parse::<usize>()
        .expect("missing nodes default");
    let proposer_nodes = subcommand_matches
        .get_one::<String>("proposer-nodes")
        .unwrap_or(&String::from("0"))
        .parse::<usize>()
        .unwrap_or(0);
    // extra beacon node added with delay
    let extra_nodes: usize = 1;
    println!("PROPOSER-NODES: {}", proposer_nodes);
    let validators_per_node = subcommand_matches
        .get_one::<String>("validators-per-node")
        .expect("missing validators-per-node default")
        .parse::<usize>()
        .expect("missing validators-per-node default");
    let log_level = subcommand_matches
        .get_one::<String>("debug-level")
        .expect("missing debug-level");

    let continue_after_checks = subcommand_matches.get_flag("continue-after-checks");
    let log_dir = subcommand_matches
        .get_one::<String>("log-dir")
        .map(PathBuf::from);
    let disable_stdout_logging = subcommand_matches.get_flag("disable-stdout-logging");

    println!("Basic Simulator:");
    println!(" nodes: {}", node_count);
    println!(" proposer-nodes: {}", proposer_nodes);
    println!(" validators-per-node: {}", validators_per_node);
    println!(" continue-after-checks: {}", continue_after_checks);
    println!(" log-dir: {:?}", log_dir);
    println!(" disable-stdout-logging: {}", disable_stdout_logging);

    // Generate the directories and keystores required for the validator clients.
    let validator_files = (0..node_count)
        .into_par_iter()
        .map(|i| {
            println!(
                "Generating keystores for validator {} of {}",
                i + 1,
                node_count
            );

            let indices =
                (i * validators_per_node..(i + 1) * validators_per_node).collect::<Vec<_>>();
            ValidatorFiles::with_keystores(&indices).unwrap()
        })
        .collect::<Vec<_>>();

    let (
        env_builder,
        logger_config,
        stdout_logging_layer,
        file_logging_layer,
        _sse_logging_layer_opt,
        libp2p_discv5_layer,
    ) = tracing_common::construct_logger(
        LoggerConfig {
            path: log_dir,
            debug_level: tracing_common::parse_level(&log_level.clone()),
            logfile_debug_level: tracing_common::parse_level(&log_level.clone()),
            log_format: None,
            logfile_format: None,
            log_color: true,
            logfile_color: false,
            disable_log_timestamp: false,
            max_log_size: 200,
            max_log_number: 5,
            compression: false,
            is_restricted: true,
            sse_logging: false,
            extra_info: false,
        },
        matches,
        EnvironmentBuilder::minimal(),
    );

    let workspace_filter = build_workspace_filter()?;
    let mut logging_layers = vec![];
    if !disable_stdout_logging {
        logging_layers.push(
            stdout_logging_layer
                .with_filter(logger_config.debug_level)
                .with_filter(workspace_filter.clone())
                .boxed(),
        );
    }
    if let Some(file_logging_layer) = file_logging_layer {
        logging_layers.push(
            file_logging_layer
                .with_filter(logger_config.logfile_debug_level)
                .with_filter(workspace_filter)
                .boxed(),
        );
    }
    if let Some(libp2p_discv5_layer) = libp2p_discv5_layer {
        logging_layers.push(
            libp2p_discv5_layer
                .with_filter(
                    EnvFilter::builder()
                        .with_default_directive(Level::DEBUG.into())
                        .from_env_lossy(),
                )
                .boxed(),
        );
    }

    if let Err(e) = tracing_subscriber::registry()
        .with(logging_layers)
        .try_init()
    {
        eprintln!("Failed to initialize dependency logging: {e}");
    }

    let mut env = env_builder.multi_threaded_tokio_runtime()?.build()?;

    let mut spec = (*env.eth2_config.spec).clone();

    let total_validator_count = validators_per_node * node_count;
    let genesis_delay = GENESIS_DELAY;

    // Convenience variables. Update these values when adding a newer fork.
    let latest_fork_version = spec.gloas_fork_version;

    // The driver moves the clock, so a slot only takes as long as the nodes need. A long slot puts
    // the real-time timeouts derived from it well above any real delay.
    spec = spec.set_slot_duration_ms::<MinimalEthSpec>(SLOT_DURATION_MS);

    spec.genesis_delay = genesis_delay;
    spec.min_genesis_time = 0;
    spec.min_genesis_active_validator_count = total_validator_count as u64;
    spec.altair_fork_epoch = Some(Epoch::new(ALTAIR_FORK_EPOCH));
    spec.bellatrix_fork_epoch = Some(Epoch::new(BELLATRIX_FORK_EPOCH));
    spec.capella_fork_epoch = Some(Epoch::new(CAPELLA_FORK_EPOCH));
    spec.deneb_fork_epoch = Some(Epoch::new(DENEB_FORK_EPOCH));
    spec.electra_fork_epoch = Some(Epoch::new(ELECTRA_FORK_EPOCH));
    spec.fulu_fork_epoch = Some(Epoch::new(FULU_FORK_EPOCH));
    spec.gloas_fork_epoch = Some(Epoch::new(GLOAS_FORK_EPOCH));
    let spec = Arc::new(spec);
    env.eth2_config.spec = spec.clone();

    let slots_per_epoch = MinimalEthSpec::slots_per_epoch();
    let initial_validator_count = spec.min_genesis_active_validator_count as usize;

    let context = env.core_context();

    let main_future = async {
        /*
         * Create a new `LocalNetwork` with one beacon node.
         */
        let max_retries = 3;
        let (network, beacon_config, mock_execution_config) = with_retry(max_retries, || {
            Box::pin(LocalNetwork::create_local_network(
                None,
                None,
                LocalNetworkParams {
                    validator_count: total_validator_count,
                    node_count,
                    extra_nodes,
                    proposer_nodes,
                    genesis_delay,
                },
                context.clone(),
            ))
        })
        .await?;

        // Add nodes to the network.
        for _ in 0..node_count {
            network
                .add_beacon_node(beacon_config.clone(), mock_execution_config.clone(), false)
                .await?;
        }

        /*
         * One by one, add proposer nodes to the network.
         */
        for _ in 0..proposer_nodes {
            println!("Adding a proposer node");
            network
                .add_beacon_node(beacon_config.clone(), mock_execution_config.clone(), true)
                .await?;
        }

        /*
         * One by one, add validators to the network.
         */
        let validator_client_count = validator_files.len();
        let executor = context.executor.clone();
        for (i, files) in validator_files.into_iter().enumerate() {
            let network_1 = network.clone();
            executor.spawn(
                async move {
                    let mut validator_config = testing_validator_config();
                    validator_config.validator_store.fee_recipient =
                        Some(SUGGESTED_FEE_RECIPIENT.into());
                    println!("Adding validator client {}", i);

                    // Enable broadcast on every 4th node.
                    if i % 4 == 0 {
                        validator_config.broadcast_topics = ApiTopic::all();
                        let beacon_nodes = vec![i, (i + 1) % node_count];
                        network_1
                            .add_validator_client_with_fallbacks(
                                validator_config,
                                beacon_nodes,
                                files,
                            )
                            .await
                    } else {
                        network_1
                            .add_validator_client(validator_config, i, files)
                            .await
                    }
                    .expect("should add validator");
                },
                "vc",
            );
        }

        // Set all payloads as valid. This effectively assumes the EL is infalliable.
        network.execution_nodes.write().iter().for_each(|node| {
            node.server.all_payloads_valid();
        });

        let driver = SimDriver::new(network.clone(), spec.clone());
        driver
            .start_at_genesis(validator_client_count, total_validator_count)
            .await?;

        let end_slot = Epoch::new(END_EPOCH).start_slot(slots_per_epoch);
        // The extra node joins without validators, and syncs while the chain keeps moving.
        let delayed_node_join_slot = Epoch::new(END_EPOCH - 3).start_slot(slots_per_epoch);
        let delayed_node_index = node_count;
        // Sync aggregates are available from the first slot after the Altair fork, and the Gloas
        // fork block still attests a Fulu parent (#9587).
        let light_client_slots = Epoch::new(ALTAIR_FORK_EPOCH).start_slot(slots_per_epoch) + 1
            ..=Epoch::new(GLOAS_FORK_EPOCH).start_slot(slots_per_epoch);
        let mut light_client_checker = LightClientUpdateChecker::default();

        for slot in (0..=end_slot.as_u64()).map(Slot::new) {
            if slot == delayed_node_join_slot {
                println!("Adding the delayed beacon node at slot {slot}");
                network
                    .add_beacon_node(beacon_config.clone(), mock_execution_config.clone(), false)
                    .await?;
                // Make the delayed node's execution node accept every payload, like the others.
                if let Some(execution_node) = network.execution_nodes.read().last() {
                    execution_node.server.all_payloads_valid();
                }
                driver.exclude_beacon_node(delayed_node_index);
            }

            driver.run_slot(slot).await?;

            // Check that the chain starts with the expected validator count.
            if slot == 1 {
                checks::verify_validator_count(&network, initial_validator_count).await?;
            }
            // Check that the transition block is finalized, before the finalized block is a
            // Gloas block without an execution payload.
            if slot == Epoch::new(TERMINAL_BLOCK / slots_per_epoch + 2).start_slot(slots_per_epoch)
            {
                checks::verify_transition_block_finalized(&network).await?;
            }
            // Check that the chain finalizes at the first given opportunity.
            if slot == Epoch::new(4).start_slot(slots_per_epoch) {
                checks::verify_all_finalized_at(&network, Epoch::new(2)).await?;
            }
            if light_client_slots.contains(&slot) {
                light_client_checker.check_slot(&network, slot).await?;
            }
        }

        driver
            .include_beacon_node_once_synced(delayed_node_index)
            .await?;

        // Check that a block was produced at every slot.
        checks::verify_full_block_production_up_to(&network, end_slot)?;
        // Check that validators greater than `spec.min_genesis_active_validator_count` are
        // onboarded.
        checks::verify_validator_count(&network, total_validator_count).await?;
        // Check that all nodes have transitioned to the required fork.
        checks::verify_fork_version(&network, latest_fork_version).await?;
        // Check that all sync aggregates are full.
        checks::verify_full_sync_aggregates_up_to(
            &network,
            // The driver checks sync committee messages from the second epoch, and each block
            // aggregates the messages of the slot before it.
            Epoch::new(ALTAIR_FORK_EPOCH + 1).start_slot(slots_per_epoch) + 1,
            end_slot,
        )
        .await?;
        // Blobs should be available immediately after the Deneb fork.
        checks::verify_full_blob_production_up_to(
            &network,
            Epoch::new(DENEB_FORK_EPOCH).start_slot(slots_per_epoch),
            end_slot,
        )
        .await?;
        checks::ensure_node_synced_up_to_slot(&network, delayed_node_index, end_slot).await?;

        // Keep the chain running if requested.
        if continue_after_checks {
            for slot in (end_slot.as_u64() + 1..).map(Slot::new) {
                driver.run_slot(slot).await?;
            }
        }
        /*
         * End the simulation by dropping the network. This will kill all running beacon nodes and
         * validator clients.
         */
        println!(
            "Simulation complete. Finished with {} beacon nodes and {} validator clients",
            network.beacon_node_count() + network.proposer_node_count(),
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
