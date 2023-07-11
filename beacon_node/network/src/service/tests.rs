// #[cfg(not(debug_assertions))]
#[cfg(test)]
mod tests {
    use std::ops::Add;
    use crate::persisted_dht::load_dht;
    use crate::{NetworkConfig, NetworkService};
    use beacon_chain::test_utils::BeaconChainHarness;
    use lighthouse_network::Enr;
    use slog::{o, Drain, Level, Logger};
    use sloggers::{null::NullLoggerBuilder, Build};
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::runtime::Runtime;
    use types::{Epoch, EthSpec, ForkName, MinimalEthSpec};

    fn get_logger(actual_log: bool) -> Logger {
        if actual_log {
            let drain = {
                let decorator = slog_term::TermDecorator::new().build();
                let decorator =
                    logging::AlignedTermDecorator::new(decorator, logging::MAX_MESSAGE_WIDTH);
                let drain = slog_term::FullFormat::new(decorator).build().fuse();
                let drain = slog_async::Async::new(drain).chan_size(2048).build();
                drain.filter_level(Level::Debug)
            };

            Logger::root(drain.fuse(), o!())
        } else {
            let builder = NullLoggerBuilder;
            builder.build().expect("should build logger")
        }
    }

    #[test]
    fn test_dht_persistence() {
        let log = get_logger(false);

        let beacon_chain = BeaconChainHarness::builder(MinimalEthSpec)
            .default_spec()
            .deterministic_keypairs(8)
            .fresh_ephemeral_store()
            .build()
            .chain;

        let store = beacon_chain.store.clone();

        let enr1 = Enr::from_str("enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8").unwrap();
        let enr2 = Enr::from_str("enr:-IS4QJ2d11eu6dC7E7LoXeLMgMP3kom1u3SE8esFSWvaHoo0dP1jg8O3-nx9ht-EO3CmG7L6OkHcMmoIh00IYWB92QABgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQIB_c-jQMOXsbjWkbN-Oj99H57gfId5pfb4wa1qxwV4CIN1ZHCCIyk").unwrap();
        let enrs = vec![enr1, enr2];

        let runtime = Arc::new(Runtime::new().unwrap());

        let (signal, exit) = exit_future::signal();
        let (shutdown_tx, _) = futures::channel::mpsc::channel(1);
        let executor = task_executor::TaskExecutor::new(
            Arc::downgrade(&runtime),
            exit,
            log.clone(),
            shutdown_tx,
        );

        let mut config = NetworkConfig::default();
        config.set_ipv4_listening_address(std::net::Ipv4Addr::UNSPECIFIED, 21212, 21212);
        config.discv5_config.table_filter = |_| true; // Do not ignore local IPs
        config.upnp_enabled = false;
        config.boot_nodes_enr = enrs.clone();
        runtime.block_on(async move {
            // Create a new network service which implicitly gets dropped at the
            // end of the block.

            let _network_service =
                NetworkService::start(beacon_chain.clone(), &config, executor, None)
                    .await
                    .unwrap();
            drop(signal);
        });

        let raw_runtime = Arc::try_unwrap(runtime).unwrap();
        raw_runtime.shutdown_timeout(tokio::time::Duration::from_secs(300));

        // Load the persisted dht from the store
        let persisted_enrs = load_dht(store);
        assert!(
            persisted_enrs.contains(&enrs[0]),
            "should have persisted the first ENR to store"
        );
        assert!(
            persisted_enrs.contains(&enrs[1]),
            "should have persisted the second ENR to store"
        );
    }

    // Test removing topic weight on old topics when a fork happens.
    #[test]
    fn test_removing_topic_weight_on_old_topics() {
        println!("slots_per_epoch: {}", MinimalEthSpec::slots_per_epoch());

        // Capella spec
        let mut spec = MinimalEthSpec::default_spec();
        spec.altair_fork_epoch = Some(Epoch::new(0));
        spec.bellatrix_fork_epoch = Some(Epoch::new(0));
        spec.capella_fork_epoch = Some(Epoch::new(1));

        let log = get_logger(true);

        let beacon_chain = BeaconChainHarness::builder(MinimalEthSpec)
            .spec(spec)
            .deterministic_keypairs(8)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .build()
            .chain;

        let (fork_name, duration_to_next_fork) = beacon_chain.duration_to_next_fork().expect("next fork");
        println!("fork_name: {fork_name}, dur:{duration_to_next_fork:?}");
        assert_eq!(fork_name, ForkName::Capella);

        let runtime = Arc::new(Runtime::new().unwrap());

        let (signal, exit) = exit_future::signal();
        let (shutdown_tx, _) = futures::channel::mpsc::channel(1);
        let executor = task_executor::TaskExecutor::new(
            Arc::downgrade(&runtime),
            exit,
            log.clone(),
            shutdown_tx,
        );


        runtime.block_on(async move {
            let mut config = NetworkConfig::default();
            config.set_ipv4_listening_address(std::net::Ipv4Addr::UNSPECIFIED, 21212, 21212);
            config.discv5_config.table_filter = |_| true; // Do not ignore local IPs
            config.upnp_enabled = false;

            let _network_service =
                NetworkService::start(beacon_chain, &config, executor, None)
                    .await
                    .unwrap();
        });

        runtime.block_on(async move {
            tokio::time::sleep(duration_to_next_fork.add(Duration::from_secs(2))).await;
        });

        drop(signal);

        // TODO: assertions
    }
}
