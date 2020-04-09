use crate::{checks, LocalNetwork};
use clap::ArgMatches;
use futures::{future, stream, Future, Stream};
use node_test_rig::{
    environment::EnvironmentBuilder, testing_client_config, ClientGenesis, ValidatorConfig,
};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn run_no_eth1_sim(matches: &ArgMatches) -> Result<(), String> {
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

    let mut env = EnvironmentBuilder::mainnet()
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

    let genesis_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "should get system time")?
        + Duration::from_secs(5);

    let slot_duration = Duration::from_millis(spec.milliseconds_per_slot);
    let total_validator_count = validators_per_node * node_count;

    let context = env.core_context();

    let mut beacon_config = testing_client_config();

    beacon_config.genesis = ClientGenesis::Interop {
        validator_count: total_validator_count,
        genesis_time: genesis_time.as_secs(),
    };
    beacon_config.dummy_eth1_backend = true;
    beacon_config.sync_eth1_chain = true;

    beacon_config.network.enr_address = Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

    let future = LocalNetwork::new(context, beacon_config.clone())
        /*
         * One by one, add beacon nodes to the network.
         */
        .and_then(move |network| {
            let network_1 = network.clone();

            stream::unfold(0..node_count - 1, move |mut iter| {
                iter.next().map(|_| {
                    network_1
                        .add_beacon_node(beacon_config.clone())
                        .map(|()| ((), iter))
                })
            })
            .collect()
            .map(|_| network)
        })
        /*
         * One by one, add validator clients to the network. Each validator client is attached to
         * a single corresponding beacon node.
         */
        .and_then(move |network| {
            let network_1 = network.clone();

            // Note: presently the validator client future will only resolve once genesis time
            // occurs. This is great for this scenario, but likely to change in the future.
            //
            // If the validator client future behaviour changes, we would need to add a new future
            // that delays until genesis. Otherwise, all of the checks that start in the next
            // future will start too early.

            stream::unfold(0..node_count, move |mut iter| {
                iter.next().map(|i| {
                    let indices = (i * validators_per_node..(i + 1) * validators_per_node)
                        .collect::<Vec<_>>();

                    network_1
                        .add_validator_client(ValidatorConfig::default(), i, indices)
                        .map(|()| ((), iter))
                })
            })
            .collect()
            .map(|_| network)
        })
        /*
         * Start the processes that will run checks on the network as it runs.
         */
        .and_then(move |network| {
            // The `final_future` either completes immediately or never completes, depending on the value
            // of `end_after_checks`.
            let final_future: Box<dyn Future<Item = (), Error = String> + Send> =
                if end_after_checks {
                    Box::new(future::ok(()).map_err(|()| "".to_string()))
                } else {
                    Box::new(future::empty().map_err(|()| "".to_string()))
                };

            future::ok(())
                // Check that the chain finalizes at the first given opportunity.
                .join(checks::verify_first_finalization(
                    network.clone(),
                    slot_duration,
                ))
                // End now or run forever, depending on the `end_after_checks` flag.
                .join(final_future)
                .map(|_| network)
        })
        /*
         * End the simulation by dropping the network. This will kill all running beacon nodes and
         * validator clients.
         */
        .map(|network| {
            println!(
                "Simulation complete. Finished with {} beacon nodes and {} validator clients",
                network.beacon_node_count(),
                network.validator_client_count()
            );

            // Be explicit about dropping the network, as this kills all the nodes. This ensures
            // all the checks have adequate time to pass.
            drop(network)
        });

    env.runtime().block_on(future)
}
