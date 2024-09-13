use crate::local_network::LocalNetworkParams;
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
const EIP7594_FORK_EPOCH: u64 = 3;
//const ELECTRA_FORK_EPOCH: u64 = 0;

const SUGGESTED_FEE_RECIPIENT: [u8; 20] =
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

pub fn run_peering_sim(matches: &ArgMatches) -> Result<(), String> {
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
    // extra beacon node added with delay
    let extra_nodes: usize = 8;
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

    println!("Peering Simulator:");
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

    spec.seconds_per_slot /= speed_up_factor;
    spec.seconds_per_slot = max(1, spec.seconds_per_slot);
    spec.genesis_delay = genesis_delay;
    spec.min_genesis_time = 0;
    spec.min_genesis_active_validator_count = total_validator_count as u64;
    spec.altair_fork_epoch = Some(Epoch::new(ALTAIR_FORK_EPOCH));
    spec.bellatrix_fork_epoch = Some(Epoch::new(BELLATRIX_FORK_EPOCH));
    spec.capella_fork_epoch = Some(Epoch::new(CAPELLA_FORK_EPOCH));
    spec.deneb_fork_epoch = Some(Epoch::new(DENEB_FORK_EPOCH));
    spec.eip7594_fork_epoch = Some(Epoch::new(EIP7594_FORK_EPOCH));
    //spec.electra_fork_epoch = Some(Epoch::new(ELECTRA_FORK_EPOCH));

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

        let mut sequence = vec![];
        let mut epoch_delay = extra_nodes as u64;
        let mut node_count = node_count;

        for _ in 0..extra_nodes {
            let network_1 = network.clone();
            let owned_mock_execution_config = mock_execution_config.clone();
            let owned_beacon_config = beacon_config.clone();
            sequence.push(async move {
                network_1
                    .add_beacon_node_with_delay(
                        owned_beacon_config,
                        owned_mock_execution_config,
                        END_EPOCH - epoch_delay,
                        slot_duration,
                        slots_per_epoch,
                    )
                    .await?;
                checks::ensure_node_synced_up_to_slot(
                    network_1,
                    // This must be set to be the node which was just created. Should be equal to
                    // `node_count`.
                    node_count,
                    Epoch::new(END_EPOCH).start_slot(slots_per_epoch),
                    slot_duration,
                )
                .await?;
                Ok::<(), String>(())
            });
            epoch_delay -= 2;
            node_count += 1;
        }

        let futures = futures::future::join_all(sequence).await;
        for res in futures {
            res?
        }

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
