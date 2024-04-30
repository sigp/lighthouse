use crate::local_network::LocalNetworkParams;
use crate::local_network::TERMINAL_BLOCK;
use crate::{checks, LocalNetwork};
use clap::ArgMatches;

use crate::retry::with_retry;
use futures::prelude::*;
use node_test_rig::{
    environment::{EnvironmentBuilder, LoggerConfig},
    testing_validator_config, ApiTopic, ValidatorFiles,
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

const SUGGESTED_FEE_RECIPIENT: [u8; 20] =
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

pub fn run_basic_sim(matches: &ArgMatches) -> Result<(), String> {
    let node_count = matches
        .get_one::<String>("nodes")
        .expect("missing nodes default")
        .parse::<usize>()
        .expect("missing nodes default");
    let proposer_nodes = matches
        .get_one::<String>("proposer-nodes")
        .unwrap_or(&String::from("0"))
        .parse::<usize>()
        .unwrap_or(0);
    println!("PROPOSER-NODES: {}", proposer_nodes);
    let validators_per_node = matches
        .get_one::<String>("validators-per-node")
        .expect("missing validators-per-node default")
        .parse::<usize>()
        .expect("missing validators-per-node default");
    let speed_up_factor = matches
        .get_one::<String>("speed-up-factor")
        .expect("missing speed-up-factor default")
        .parse::<u64>()
        .expect("missing speed-up-factor default");
    let log_level = matches
        .get_one::<String>("debug-level")
        .expect("missing debug-level");

    let continue_after_checks = matches.get_flag("continue-after-checks");

    println!("Basic Simulator:");
    println!(" nodes: {}", node_count);
    println!(" proposer-nodes: {}", proposer_nodes);
    println!(" validators-per-node: {}", validators_per_node);
    println!(" speed-up-factor: {}", speed_up_factor);
    println!(" continue-after-checks: {}", continue_after_checks);

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

    let total_validator_count = validators_per_node * node_count;
    let genesis_delay = GENESIS_DELAY;

    // Convenience variables. Update these values when adding a newer fork.
    let latest_fork_version = spec.deneb_fork_version;
    let latest_fork_start_epoch = DENEB_FORK_EPOCH;

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
                    validator_config.fee_recipient = Some(SUGGESTED_FEE_RECIPIENT.into());
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

        let duration_to_genesis = network.duration_to_genesis().await;
        println!("Duration to genesis: {}", duration_to_genesis.as_secs());
        sleep(duration_to_genesis).await;

        /*
         * Start the checks that ensure the network performs as expected.
         *
         * We start these checks immediately after the validators have started. This means we're
         * relying on the validator futures to all return immediately after genesis so that these
         * tests start at the right time. Whilst this is works well for now, it's subject to
         * breakage by changes to the VC.
         */
        let network_1 = network.clone();

        let (
            finalization,
            block_prod,
            validator_count,
            onboarding,
            fork,
            sync_aggregate,
            transition,
            light_client_update,
            blobs,
            start_node_with_delay,
            sync,
        ) = futures::join!(
            // Check that the chain finalizes at the first given opportunity.
            checks::verify_first_finalization(network.clone(), slot_duration),
            // Check that a block is produced at every slot.
            checks::verify_full_block_production_up_to(
                network.clone(),
                Epoch::new(END_EPOCH).start_slot(slots_per_epoch),
                slot_duration,
            ),
            // Check that the chain starts with the expected validator count.
            checks::verify_initial_validator_count(
                network.clone(),
                slot_duration,
                initial_validator_count,
            ),
            // Check that validators greater than `spec.min_genesis_active_validator_count` are
            // onboarded at the first possible opportunity.
            checks::verify_validator_onboarding(
                network.clone(),
                slot_duration,
                total_validator_count,
            ),
            // Check that all nodes have transitioned to the required fork.
            checks::verify_fork_version(
                network.clone(),
                Epoch::new(latest_fork_start_epoch),
                slot_duration,
                latest_fork_version,
            ),
            // Check that all sync aggregates are full.
            checks::verify_full_sync_aggregates_up_to(
                network.clone(),
                // Start checking for sync_aggregates at `FORK_EPOCH + 1` to account for
                // inefficiencies in finding subnet peers at the `fork_slot`.
                Epoch::new(ALTAIR_FORK_EPOCH + 1).start_slot(slots_per_epoch),
                Epoch::new(END_EPOCH).start_slot(slots_per_epoch),
                slot_duration,
            ),
            // Check that the transition block is finalized.
            checks::verify_transition_block_finalized(
                network.clone(),
                Epoch::new(TERMINAL_BLOCK / slots_per_epoch),
                slot_duration,
                true,
            ),
            checks::verify_light_client_updates(
                network.clone(),
                // Sync aggregate available from slot 1 after Altair fork transition.
                Epoch::new(ALTAIR_FORK_EPOCH).start_slot(slots_per_epoch) + 1,
                Epoch::new(END_EPOCH).start_slot(slots_per_epoch),
                slot_duration
            ),
            checks::verify_full_blob_production_up_to(
                network.clone(),
                // Blobs should be available immediately after the Deneb fork.
                Epoch::new(DENEB_FORK_EPOCH).start_slot(slots_per_epoch),
                Epoch::new(END_EPOCH).start_slot(slots_per_epoch),
                slot_duration
            ),
            network_1.add_beacon_node_with_delay(
                beacon_config.clone(),
                mock_execution_config.clone(),
                END_EPOCH - 1,
                slot_duration,
                slots_per_epoch
            ),
            checks::ensure_node_synced_up_to_slot(
                network.clone(),
                // This must be set to be the node which was just created. Should be equal to
                // `node_count`.
                node_count,
                Epoch::new(END_EPOCH).start_slot(slots_per_epoch),
                slot_duration,
            ),
        );

        block_prod?;
        finalization?;
        validator_count?;
        onboarding?;
        fork?;
        sync_aggregate?;
        transition?;
        light_client_update?;
        blobs?;
        start_node_with_delay?;
        sync?;

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
