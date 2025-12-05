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
    let stale_node_count = subcommand_matches
        .get_one::<String>("stale-nodes")
        .expect("missing nodes default")
        .parse::<usize>()
        .expect("missing nodes default");
    // extra beacon node added with delay
    let extra_nodes: usize = 1;
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
    println!(" stale-nodes: {}", stale_node_count);
    println!(" validators-per-node: {}", validators_per_node);
    println!(" speed-up-factor: {}", speed_up_factor);
    println!(" continue-after-checks: {}", continue_after_checks);
    println!(" log-dir: {:?}", log_dir);
    println!(" disable-stdout-logging: {}", disable_stdout_logging);

    // Generate the directories and keystores required for the validator clients.
    // Include stale nodes in total count
    let total_nodes_with_validators = node_count + stale_node_count;
    let validator_files = (0..total_nodes_with_validators)
        .into_par_iter()
        .map(|i| {
            println!(
                "Generating keystores for validator {} of {}",
                i + 1,
                total_nodes_with_validators
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
                    proposer_nodes: 0,
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

        // Create stale spec and context before adding stale nodes
        let mut stale_spec = (*spec).clone();
        stale_spec.electra_fork_epoch = Some(Epoch::new(100));
        let stale_spec = Arc::new(stale_spec);

        let mut stale_context = context.clone();
        stale_context.eth2_config.spec = stale_spec;

        // Configure fixed HTTP ports for stale nodes so validators can reconnect after restart
        const STALE_NODE_HTTP_PORT_BASE: u16 = 6000;

        // Add stale nodes with fixed HTTP ports
        for i in 0..stale_node_count {
            let mut stale_config = beacon_config.clone();
            // Set fixed HTTP port for this stale node
            stale_config.http_api.listen_port = STALE_NODE_HTTP_PORT_BASE + i as u16;

            network
                .add_beacon_node_with_context(
                    stale_config,
                    mock_execution_config.clone(),
                    stale_context.clone(),
                    false,
                )
                .await?;
        }

        /*
         * Add validators to all nodes (canonical + proposer + stale).
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

        // Set all payloads as valid. This effectively assumes the EL is infalliable.
        network.execution_nodes.write().iter().for_each(|node| {
            node.server.all_payloads_valid();
        });

        let duration_to_genesis = network.duration_to_genesis().await?;
        println!("Duration to genesis: {}", duration_to_genesis.as_secs());
        sleep(duration_to_genesis).await;

        let test_sequence = async {
            println!("Waiting for canonical chain to finalize past Electra fork...");
            checks::epoch_delay(Epoch::new(4), slot_duration, slots_per_epoch).await;
            println!("Canonical chain finalized at epoch 4");

            // Verify chains have diverged
            let canonical_head = network.beacon_nodes.read()[0]
                .client
                .beacon_chain()
                .expect("should have beacon chain")
                .head_snapshot()
                .beacon_block_root;

            let stale_head = network.beacon_nodes.read()[node_count]
                .client
                .beacon_chain()
                .expect("should have beacon chain")
                .head_snapshot()
                .beacon_block_root;

            if canonical_head == stale_head {
                return Err(
                    "Chains did not diverge! Stale and canonical heads are the same".to_string(),
                );
            }
            println!("Verified: Chains have diverged");
            println!("  Canonical head: {:?}", canonical_head);
            println!("  Stale head: {:?}", stale_head);

            println!("\nShutting down stale nodes to prepare for restart...");

            // Shutdown stale nodes and preserve their datadirs
            let mut stale_datadirs = Vec::new();
            for i in (0..stale_node_count).rev() {
                // Remove from end to avoid index shifting
                let node_index = node_count + i;
                println!("Removing stale node at index {}", node_index);
                let datadir = network.remove_beacon_node(node_index);
                println!("  Preserved datadir: {}", datadir.display());
                stale_datadirs.push(datadir);
            }

            // Give nodes time to fully shutdown and release ports
            println!("Waiting 2 seconds for clean shutdown...");
            tokio::time::sleep(Duration::from_secs(2)).await;

            println!("\nRestarting stale nodes with CORRECT Electra epoch configuration...");

            // Restart each stale node with canonical context (correct fork config)
            // Reverse iterator to maintain original node order
            for (i, datadir) in stale_datadirs.into_iter().rev().enumerate() {
                println!("Restarting stale node {} with correct config", i);
                println!("  Using datadir: {}", datadir.display());

                // Create config with fixed HTTP port (same as before)
                let mut restart_beacon_config = beacon_config.clone();
                restart_beacon_config.http_api.listen_port = STALE_NODE_HTTP_PORT_BASE + i as u16;

                network
                    .add_beacon_node_with_datadir(
                        restart_beacon_config,
                        mock_execution_config.clone(),
                        context.clone(), // Use canonical context (Electra epoch = 2)
                        datadir,
                    )
                    .await
                    .map_err(|e| format!("Failed to restart stale node {}: {}", i, e))?;

                println!("  Successfully restarted stale node {}", i);
            }

            println!("\nAll stale nodes restarted. Waiting for network to stabilize...");

            // Wait for restarted nodes to:
            // 1. Trigger fork revert (revert to pre-Electra blocks)
            // 2. Sync to canonical chain head
            // 3. Participate in finalization
            // Wait until epoch 8 (4 epochs after restart, plenty of time)
            checks::epoch_delay(Epoch::new(8), slot_duration, slots_per_epoch).await;

            // Verify all nodes are using correct Electra fork version
            println!("Verifying all nodes are using correct Electra fork version...");
            checks::verify_fork_version(
                network.clone(),
                Epoch::new(0), // Don't delay, check immediately (we're already past epoch 8)
                slot_duration,
                spec.electra_fork_version,
            )
            .await?;
            println!("✓ All nodes using correct fork version");

            println!("\nVerifying all nodes finalized at same epoch...");
            checks::verify_all_finalized_at(network.clone(), Epoch::new(6)).await?;
            println!("✓ All nodes finalized at epoch 6");

            println!("\n✓ SUCCESS: All nodes recovered and are in sync!");
            println!("✓ Fork revert logic worked correctly");

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
