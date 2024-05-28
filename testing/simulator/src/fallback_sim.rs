use crate::local_network::LocalNetworkParams;
use crate::{checks, LocalNetwork};
use clap::ArgMatches;

use crate::retry::with_retry;
use futures::prelude::*;
use node_test_rig::{
    environment::{EnvironmentBuilder, LoggerConfig},
    testing_validator_config, ValidatorFiles,
};
use rayon::prelude::*;
use std::cmp::max;
use std::time::Duration;
use tokio::time::sleep;
use types::{Epoch, EthSpec, MinimalEthSpec};

const END_EPOCH: u64 = 16;
const GENESIS_DELAY: u64 = 32;
const ALTAIR_FORK_EPOCH: u64 = 0;
const BELLATRIX_FORK_EPOCH: u64 = 0;
const CAPELLA_FORK_EPOCH: u64 = 1;
const DENEB_FORK_EPOCH: u64 = 2;
//const ELECTRA_FORK_EPOCH: u64 = 3;

// Since simulator tests are non-deterministic and there is a non-zero chance of missed
// attestations, define an acceptable network-wide attestation performance.
//
// This has potential to block CI so it should be set conservatively enough that spurious failures
// don't become very common, but not so conservatively that regressions to the fallback mechanism
// cannot be detected.
const ACCEPTABLE_FALLBACK_ATTESTATION_HIT_PERCENTAGE: f64 = 85.0;

const SUGGESTED_FEE_RECIPIENT: [u8; 20] =
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

pub fn run_fallback_sim(matches: &ArgMatches) -> Result<(), String> {
    let vc_count = matches
        .get_one::<String>("vc-count")
        .expect("missing vc-count default")
        .parse::<usize>()
        .expect("missing vc-count default");

    let validators_per_vc = matches
        .get_one::<String>("validators-per-vc")
        .expect("missing validators-per-vc default")
        .parse::<usize>()
        .expect("missing validators-per-vc default");

    let bns_per_vc = matches
        .get_one::<String>("bns-per-vc")
        .expect("missing bns-per-vc default")
        .parse::<usize>()
        .expect("missing bns-per-vc default");

    assert!(bns_per_vc > 1);
    let speed_up_factor = matches
        .get_one::<String>("speed-up-factor")
        .expect("missing speed-up-factor default")
        .parse::<u64>()
        .expect("missing speed-up-factor default");

    let log_level = matches
        .get_one::<String>("debug-level")
        .expect("missing debug-level default");

    let continue_after_checks = matches.get_flag("continue-after-checks");

    println!("Fallback Simulator:");
    println!(" vc-count: {}", vc_count);
    println!(" validators-per-vc: {}", validators_per_vc);
    println!(" bns-per-vc: {}", bns_per_vc);
    println!(" speed-up-factor: {}", speed_up_factor);
    println!(" continue-after-checks: {}", continue_after_checks);

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

    let mut env = EnvironmentBuilder::minimal()
        .initialize_logger(LoggerConfig {
            path: None,
            debug_level: log_level.clone(),
            logfile_debug_level: log_level.clone(),
            log_format: None,
            logfile_format: None,
            log_color: false,
            disable_log_timestamp: false,
            max_log_size: 0,
            max_log_number: 0,
            compression: false,
            is_restricted: true,
            sse_logging: false,
        })?
        .multi_threaded_tokio_runtime()?
        .build()?;

    let spec = &mut env.eth2_config.spec;

    let total_validator_count = validators_per_vc * vc_count;
    let node_count = vc_count * bns_per_vc;

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
    //spec.electra_fork_epoch = Some(Epoch::new(ELECTRA_FORK_EPOCH));

    let slot_duration = Duration::from_secs(spec.seconds_per_slot);
    let slots_per_epoch = MinimalEthSpec::slots_per_epoch();

    let disconnection_epoch = 1;
    let epochs_disconnected = 14;

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
                    validator_config.fee_recipient = Some(SUGGESTED_FEE_RECIPIENT.into());
                    println!("Adding validator client {}", i);
                    network_1
                        .add_validator_client_with_fallbacks(
                            validator_config,
                            i,
                            beacon_nodes,
                            files,
                        )
                        .await
                        .expect("should add validator");
                },
                "vc",
            );
        }

        let duration_to_genesis = network.duration_to_genesis().await;
        println!("Duration to genesis: {}", duration_to_genesis.as_secs());
        sleep(duration_to_genesis).await;

        let test_sequence = async {
            checks::epoch_delay(
                Epoch::new(disconnection_epoch),
                slot_duration,
                slots_per_epoch,
            )
            .await;
            // Iterate through each VC and disconnect all BNs but the last node for each VC.
            for i in 0..vc_count {
                for j in 0..(bns_per_vc - 1) {
                    let node_index = bns_per_vc * i + j;
                    checks::disconnect_from_execution_layer(network.clone(), node_index).await?;
                }
            }
            checks::epoch_delay(
                Epoch::new(epochs_disconnected),
                slot_duration,
                slots_per_epoch,
            )
            .await;
            // Enable all BNs.
            for i in 0..node_count {
                checks::reconnect_to_execution_layer(network.clone(), i).await?;
            }
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

        let (sequence, check_attestations, block_production) = futures::join!(
            test_sequence,
            checks::check_attestation_correctness(
                network.clone(),
                0,
                END_EPOCH,
                slot_duration,
                // Use the last node index as this will never have been disabled.
                node_count - 1,
                ACCEPTABLE_FALLBACK_ATTESTATION_HIT_PERCENTAGE,
            ),
            checks::verify_full_block_production_up_to(
                network.clone(),
                Epoch::new(END_EPOCH).start_slot(slots_per_epoch),
                slot_duration,
            ),
        );
        sequence?;
        block_production?;
        check_attestations?;

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
