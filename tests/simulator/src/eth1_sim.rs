use crate::{checks, LocalNetwork, E};
use clap::ArgMatches;
use eth1_test_rig::GanacheEth1Instance;
use futures::prelude::*;
use node_test_rig::{
    environment::EnvironmentBuilder, testing_client_config, ClientGenesis, ValidatorConfig,
};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

pub fn run_eth1_sim(matches: &ArgMatches) -> Result<(), String> {
    let node_count = value_t!(matches, "nodes", usize).expect("missing nodes default");
    let validators_per_node = value_t!(matches, "validators_per_node", usize)
        .expect("missing validators_per_node default");
    let speed_up_factor =
        value_t!(matches, "speed_up_factor", u64).expect("missing speed_up_factor default");
    let mut end_after_checks = true;
    if matches.is_present("end_after_checks") {
        end_after_checks = false;
    }

    println!("Beacon Chain Simulator:");
    println!(" nodes:{}", node_count);
    println!(" validators_per_node:{}", validators_per_node);
    println!(" end_after_checks:{}", end_after_checks);

    let log_level = "debug";
    let log_format = None;

    let mut env = EnvironmentBuilder::minimal()
        .async_logger(log_level, log_format)?
        .multi_threaded_tokio_runtime()?
        .build()?;

    let eth1_block_time = Duration::from_millis(15_000 / speed_up_factor);

    let spec = &mut env.eth2_config.spec;

    spec.milliseconds_per_slot /= speed_up_factor;
    spec.eth1_follow_distance = 16;
    spec.min_genesis_delay = eth1_block_time.as_secs() * spec.eth1_follow_distance * 2;
    spec.min_genesis_time = 0;
    spec.min_genesis_active_validator_count = 64;
    spec.seconds_per_eth1_block = 1;

    let slot_duration = Duration::from_millis(spec.milliseconds_per_slot);
    let initial_validator_count = spec.min_genesis_active_validator_count as usize;
    let total_validator_count = validators_per_node * node_count;
    let deposit_amount = env.eth2_config.spec.max_effective_balance;

    let context = env.core_context();

    let main_future = async {
        /*
         * Deploy the deposit contract, spawn tasks to keep creating new blocks and deposit
         * validators.
         */
        let ganache_eth1_instance = GanacheEth1Instance::new().await?;
        let deposit_contract = ganache_eth1_instance.deposit_contract;
        let ganache = ganache_eth1_instance.ganache;
        let eth1_endpoint = ganache.endpoint();
        let deposit_contract_address = deposit_contract.address();

        // Start a timer that produces eth1 blocks on an interval.
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(eth1_block_time);
            while let Some(_) = interval.next().await {
                let _ = ganache.evm_mine().await;
            }
        });

        // Submit deposits to the deposit contract.
        tokio::spawn(async move {
            for i in 0..total_validator_count {
                println!("Submitting deposit for validator {}...", i);
                let _ = deposit_contract
                    .deposit_deterministic_async::<E>(i, deposit_amount)
                    .await;
            }
        });

        let mut beacon_config = testing_client_config();

        beacon_config.genesis = ClientGenesis::DepositContract;
        beacon_config.eth1.endpoint = eth1_endpoint;
        beacon_config.eth1.deposit_contract_address = deposit_contract_address;
        beacon_config.eth1.deposit_contract_deploy_block = 0;
        beacon_config.eth1.lowest_cached_block_number = 0;
        beacon_config.eth1.follow_distance = 1;
        beacon_config.dummy_eth1_backend = false;
        beacon_config.sync_eth1_chain = true;

        beacon_config.network.enr_address = Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        /*
         * Create a new `LocalNetwork` with one beacon node.
         */
        let network = LocalNetwork::new(context, beacon_config.clone()).await?;
        /*
         * One by one, add beacon nodes to the network.
         */

        for _ in 0..node_count - 1 {
            network.add_beacon_node(beacon_config.clone()).await?;
        }
        /*
         * One by one, add validator clients to the network. Each validator client is attached to
         * a single corresponding beacon node.
         */

        // Note: presently the validator client future will only resolve once genesis time
        // occurs. This is great for this scenario, but likely to change in the future.
        //
        // If the validator client future behaviour changes, we would need to add a new future
        // that delays until genesis. Otherwise, all of the checks that start in the next
        // future will start too early.

        for i in 0..node_count {
            let indices =
                (i * validators_per_node..(i + 1) * validators_per_node).collect::<Vec<_>>();
            network
                .add_validator_client(ValidatorConfig::default(), i, indices)
                .await?;
        }

        /*
         * Start the processes that will run checks on the network as it runs.
         */

        let _err = futures::join!(
            // Check that the chain finalizes at the first given opportunity.
            checks::verify_first_finalization(network.clone(), slot_duration),
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
            )
        );

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

    Ok(env.runtime().block_on(main_future).unwrap())
}
