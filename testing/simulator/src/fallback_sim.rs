use crate::driver::SimDriver;
use crate::local_network::LocalNetworkParams;
use crate::{LocalNetwork, checks};
use clap::ArgMatches;

use crate::retry::with_retry;
use environment::tracing_common;
use logging::build_workspace_filter;
use node_test_rig::{
    ValidatorFiles,
    environment::{EnvironmentBuilder, LoggerConfig},
    testing_validator_config,
};
use rayon::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::Level;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
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

// Since simulator tests are non-deterministic and there is a non-zero chance of missed
// attestations, define an acceptable network-wide attestation performance.
//
// This has potential to block CI so it should be set conservatively enough that spurious failures
// don't become very common, but not so conservatively that regressions to the fallback mechanism
// cannot be detected.
const ACCEPTABLE_FALLBACK_ATTESTATION_HIT_PERCENTAGE: f64 = 95.0;

const SUGGESTED_FEE_RECIPIENT: [u8; 20] =
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

pub fn run_fallback_sim(matches: &ArgMatches) -> Result<(), String> {
    let (_name, subcommand_matches) = matches.subcommand().expect("subcommand");
    let vc_count = subcommand_matches
        .get_one::<String>("vc-count")
        .expect("missing vc-count default")
        .parse::<usize>()
        .expect("missing vc-count default");

    let validators_per_vc = subcommand_matches
        .get_one::<String>("validators-per-vc")
        .expect("missing validators-per-vc default")
        .parse::<usize>()
        .expect("missing validators-per-vc default");

    let bns_per_vc = subcommand_matches
        .get_one::<String>("bns-per-vc")
        .expect("missing bns-per-vc default")
        .parse::<usize>()
        .expect("missing bns-per-vc default");

    assert!(bns_per_vc > 1);

    let log_level = subcommand_matches
        .get_one::<String>("debug-level")
        .expect("missing debug-level default");

    let continue_after_checks = subcommand_matches.get_flag("continue-after-checks");

    let log_dir = subcommand_matches
        .get_one::<String>("log-dir")
        .map(PathBuf::from);

    let disable_stdout_logging = subcommand_matches.get_flag("disable-stdout-logging");

    println!("Fallback Simulator:");
    println!(" vc-count: {}", vc_count);
    println!(" validators-per-vc: {}", validators_per_vc);
    println!(" bns-per-vc: {}", bns_per_vc);
    println!(" continue-after-checks: {}", continue_after_checks);
    println!(" log-dir: {:?}", log_dir);
    println!(" disable-stdout-logging: {}", disable_stdout_logging);

    // Generate the directories and keystores required for the validator clients.
    let validator_files = (0..vc_count)
        .into_par_iter()
        .map(|i| {
            println!(
                "Generating keystores for validator {} of {}",
                i + 1,
                vc_count
            );

            let indices = (i * validators_per_vc..(i + 1) * validators_per_vc).collect::<Vec<_>>();
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

    let total_validator_count = validators_per_vc * vc_count;
    let node_count = vc_count * bns_per_vc;

    let genesis_delay = GENESIS_DELAY;

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

    let disconnection_epoch = 1;

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
                    extra_nodes: 0,
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

        /*
         * One by one, add validators to the network.
         */
        let executor = context.executor.clone();
        for (i, files) in validator_files.into_iter().enumerate() {
            let network_1 = network.clone();

            let mut beacon_nodes = Vec::with_capacity(vc_count * bns_per_vc);
            // Each VC gets a unique set of BNs which are not shared with any other VC.
            for j in 0..bns_per_vc {
                beacon_nodes.push(bns_per_vc * i + j)
            }

            executor.spawn(
                async move {
                    let mut validator_config = testing_validator_config();
                    validator_config.validator_store.fee_recipient =
                        Some(SUGGESTED_FEE_RECIPIENT.into());
                    println!("Adding validator client {}", i);
                    network_1
                        .add_validator_client_with_fallbacks(validator_config, beacon_nodes, files)
                        .await
                        .expect("should add validator");
                },
                "vc",
            );
        }

        let driver = SimDriver::new(network.clone(), spec.clone());
        driver
            .start_at_genesis(vc_count, total_validator_count)
            .await?;

        let disconnection_slot = Epoch::new(disconnection_epoch).start_slot(slots_per_epoch);
        let end_slot = Epoch::new(END_EPOCH).start_slot(slots_per_epoch);

        for slot in (0..=end_slot.as_u64()).map(Slot::new) {
            if slot == disconnection_slot {
                // Disconnect all BNs but the last node for each VC until the end of the
                // simulation. They still import blocks optimistically, and the VCs keep using
                // them until their next health check, so the driver keeps checking them.
                for i in 0..vc_count {
                    for j in 0..(bns_per_vc - 1) {
                        let node_index = bns_per_vc * i + j;
                        checks::disconnect_from_execution_layer(&network, node_index)?;
                    }
                }
            }
            driver.run_slot(slot).await?;
        }

        checks::verify_full_block_production_up_to(&network, end_slot)?;
        checks::check_attestation_correctness(
            &network,
            0,
            END_EPOCH,
            // Use the last node index as this will never have been disabled.
            node_count - 1,
            ACCEPTABLE_FALLBACK_ATTESTATION_HIT_PERCENTAGE,
        )
        .await?;

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
