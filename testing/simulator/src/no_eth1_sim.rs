use crate::{checks, LocalNetwork};
use clap::ArgMatches;
use futures::prelude::*;
use node_test_rig::{
    environment::EnvironmentBuilder, testing_client_config, testing_validator_config,
    ClientGenesis, ValidatorFiles,
};
use rayon::prelude::*;
use std::cmp::max;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::{sleep_until, Instant};
use types::{Epoch, EthSpec, MainnetEthSpec};

pub fn run_no_eth1_sim(matches: &ArgMatches) -> Result<(), String> {
    let node_count = value_t!(matches, "nodes", usize).expect("missing nodes default");
    let validators_per_node = value_t!(matches, "validators_per_node", usize)
        .expect("missing validators_per_node default");
    let speed_up_factor =
        value_t!(matches, "speed_up_factor", u64).expect("missing speed_up_factor default");
    let continue_after_checks = matches.is_present("continue_after_checks");

    println!("Beacon Chain Simulator:");
    println!(" nodes:{}", node_count);
    println!(" validators_per_node:{}", validators_per_node);
    println!(" continue_after_checks:{}", continue_after_checks);

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

    let log_level = "debug";
    let log_format = None;

    let mut env = EnvironmentBuilder::mainnet()
        .async_logger(log_level, log_format)?
        .multi_threaded_tokio_runtime()?
        .build()?;

    let eth1_block_time = Duration::from_millis(15_000 / speed_up_factor);

    let spec = &mut env.eth2_config.spec;

    let total_validator_count = validators_per_node * node_count;

    spec.seconds_per_slot /= speed_up_factor;
    spec.seconds_per_slot = max(1, spec.seconds_per_slot);
    spec.eth1_follow_distance = 16;
    spec.genesis_delay = eth1_block_time.as_secs() * spec.eth1_follow_distance * 2;
    spec.min_genesis_time = 0;
    spec.min_genesis_active_validator_count = total_validator_count as u64;
    spec.seconds_per_eth1_block = 1;

    let genesis_delay = Duration::from_secs(5);
    let genesis_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "should get system time")?
        + genesis_delay;
    let genesis_instant = Instant::now() + genesis_delay;

    let slot_duration = Duration::from_secs(spec.seconds_per_slot);

    let context = env.core_context();

    let mut beacon_config = testing_client_config();

    beacon_config.genesis = ClientGenesis::Interop {
        validator_count: total_validator_count,
        genesis_time: genesis_time.as_secs(),
    };
    beacon_config.dummy_eth1_backend = true;
    beacon_config.sync_eth1_chain = true;

    beacon_config.network.enr_address = Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

    let main_future = async {
        let network = LocalNetwork::new(context, beacon_config.clone()).await?;
        /*
         * One by one, add beacon nodes to the network.
         */

        for _ in 0..node_count - 1 {
            network.add_beacon_node(beacon_config.clone()).await?;
        }

        /*
         * Create a future that will add validator clients to the network. Each validator client is
         * attached to a single corresponding beacon node.
         */
        let add_validators_fut = async {
            for (i, files) in validator_files.into_iter().enumerate() {
                network
                    .add_validator_client(testing_validator_config(), i, files, i % 2 == 0)
                    .await?;
            }

            Ok::<(), String>(())
        };

        /*
         * The processes that will run checks on the network as it runs.
         */
        let checks_fut = async {
            sleep_until(genesis_instant).await;

            let (finalization, block_prod) = futures::join!(
                // Check that the chain finalizes at the first given opportunity.
                checks::verify_first_finalization(network.clone(), slot_duration),
                // Check that a block is produced at every slot.
                checks::verify_full_block_production_up_to(
                    network.clone(),
                    Epoch::new(4).start_slot(MainnetEthSpec::slots_per_epoch()),
                    slot_duration,
                )
            );
            finalization?;
            block_prod?;

            Ok::<(), String>(())
        };

        let (add_validators, start_checks) = futures::join!(add_validators_fut, checks_fut);

        add_validators?;
        start_checks?;

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

    env.runtime()
        .block_on(tokio_compat_02::FutureExt::compat(main_future))
        .unwrap();

    env.fire_signal();
    env.shutdown_on_idle();
    Ok(())
}
