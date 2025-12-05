use crate::local_network::LocalNetworkParams;
use crate::{LocalNetwork, checks};
use clap::ArgMatches;

use crate::retry::with_retry;
use futures::prelude::*;
use node_test_rig::{
    ApiTopic, ValidatorFiles,
    environment::{EnvironmentBuilder, LoggerConfig},
    testing_validator_config,
};
use rayon::prelude::*;
use std::cmp::max;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use environment::tracing_common;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use logging::build_workspace_filter;
use tokio::time::sleep;
use tracing::Level;
use types::{Epoch, EthSpec, MinimalEthSpec};

// const END_EPOCH: u64 = 16;
const GENESIS_DELAY: u64 = 38;
const ALTAIR_FORK_EPOCH: u64 = 0;
const BELLATRIX_FORK_EPOCH: u64 = 0;
const CAPELLA_FORK_EPOCH: u64 = 0;
const DENEB_FORK_EPOCH: u64 = 0;
const ELECTRA_FORK_EPOCH: u64 = 2;
// const FULU_FORK_EPOCH: u64 = 3;
// const GLOAS_FORK_EPOCH: u64 = 4;

const SUGGESTED_FEE_RECIPIENT: [u8; 20] =
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

#[allow(clippy::large_stack_frames)]
pub fn run_fork_revert_sim(matches: &ArgMatches) -> Result<(), String> {
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
    let stale_node_count = subcommand_matches
        .get_one::<String>("stale-nodes")
        .expect("missing nodes default")
        .parse::<usize>()
        .expect("missing nodes default");
    // extra beacon node added with delay
    let extra_nodes: usize = 1;
    println!("PROPOSER-NODES: {}", proposer_nodes);
    let validators_per_node = subcommand_matches
        .get_one::<String>("validators-per-node")
        .expect("missing validators-per-node default")
        .parse::<usize>()
        .expect("missing validators-per-node default");
    let speed_up_factor = subcommand_matches
        .get_one::<String>("speed-up-factor")
        .expect("missing speed-up-factor default")
        .parse::<u64>()
        .expect("missing speed-up-factor default");
    let log_level = subcommand_matches
        .get_one::<String>("debug-level")
        .expect("missing debug-level");

    let continue_after_checks = subcommand_matches.get_flag("continue-after-checks");
    let log_dir = subcommand_matches
        .get_one::<String>("log-dir")
        .map(PathBuf::from);
    let disable_stdout_logging = subcommand_matches.get_flag("disable-stdout-logging");

    println!("Fork Revert Simulator:");
    println!(" nodes: {}", node_count);
    println!(" proposer-nodes: {}", proposer_nodes);
    println!(" stale-nodes: {}", stale_node_count);
    println!(" validators-per-node: {}", validators_per_node);
    println!(" speed-up-factor: {}", speed_up_factor);
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
    let latest_fork_version = spec.electra_fork_version;
    let latest_fork_start_epoch = ELECTRA_FORK_EPOCH;

    spec.seconds_per_slot /= speed_up_factor;
    spec.seconds_per_slot = max(1, spec.seconds_per_slot);
    spec.genesis_delay = genesis_delay;
    spec.min_genesis_time = 0;
    spec.min_genesis_active_validator_count = total_validator_count as u64;
    spec.altair_fork_epoch = Some(Epoch::new(ALTAIR_FORK_EPOCH));
    spec.bellatrix_fork_epoch = Some(Epoch::new(BELLATRIX_FORK_EPOCH));
    spec.capella_fork_epoch = Some(Epoch::new(CAPELLA_FORK_EPOCH));
    spec.deneb_fork_epoch = Some(Epoch::new(DENEB_FORK_EPOCH));
    spec.electra_fork_epoch = Some(Epoch::new(ELECTRA_FORK_EPOCH));
    let spec = Arc::new(spec);
    env.eth2_config.spec = spec.clone();

    let slot_duration = Duration::from_secs(spec.seconds_per_slot);
    let slots_per_epoch = MinimalEthSpec::slots_per_epoch();

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
                                i,
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

        // Create stale spec
        let mut stale_spec = (*spec).clone();
        stale_spec.electra_fork_epoch = Some(Epoch::new(100));
        let stale_spec = Arc::new(stale_spec);

        // Create stale context
        let mut stale_context = context.clone();
        stale_context.eth2_config.spec = stale_spec;

        // Add stale nodes
        for _ in 0..stale_node_count {
            network
                .add_beacon_node_with_context(
                    beacon_config.clone(),
                    mock_execution_config.clone(),
                    stale_context.clone(),
                    false,
                )
                .await?;
        }

        // Set all payloads as valid. This effectively assumes the EL is infalliable.
        network.execution_nodes.write().iter().for_each(|node| {
            node.server.all_payloads_valid();
        });

        let duration_to_genesis = network.duration_to_genesis().await?;
        println!("Duration to genesis: {}", duration_to_genesis.as_secs());
        sleep(duration_to_genesis).await;

        let test_sequence = async {
            // Delay until canonical chain finalizes
            checks::epoch_delay(Epoch::new(4), slot_duration, slots_per_epoch).await;

            // Iterate through each stale node and:
            // 1. Shut them down, saving their files.
            // 2. Restart with the correct config.

            // Delay until the chain finalizes with all nodes

            Ok::<(), String>(())
        };

        /*
         * Start the checks that ensure the network performs as expected.
         *
         * We start these checks immediately after the validators have started. This means we're
         * relying on the validator futures to all return immediately after genesis so that these
         * tests start at the right time. Whilst this is works well for now, it's subject to
         * breakage by changes to the VC.
         */

        let (sequence,) = futures::join!(test_sequence,);

        sequence?;

        // The `final_future` either completes immediately or never completes, depending on the value
        // of `continue_after_checks`.

        if continue_after_checks {
            future::pending::<()>().await;
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
