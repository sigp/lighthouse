#[cfg(not(debug_assertions))]
#[cfg(test)]
mod tests {
    use crate::persisted_dht::load_dht;
    use crate::{NetworkConfig, Service};
    use beacon_chain::builder::BeaconChainBuilder;
    use beacon_chain::slot_clock::TestingSlotClock;
    use eth2_libp2p::Enr;
    use futures::{Future, IntoFuture};
    use genesis::{generate_deterministic_keypairs, interop_genesis_state};
    use slog::Logger;
    use sloggers::{null::NullLoggerBuilder, Build};
    use std::str::FromStr;
    use std::sync::Arc;
    use store::{migrate::NullMigrator, SimpleDiskStore};
    use tempdir::TempDir;
    use tokio::runtime::Runtime;
    use types::{EthSpec, MinimalEthSpec};

    fn get_logger() -> Logger {
        let builder = NullLoggerBuilder;
        builder.build().expect("should build logger")
    }

    #[test]
    fn test_dht_persistence() {
        // Create new LevelDB store
        let path = TempDir::new("persistence_test").unwrap();
        let store = Arc::new(SimpleDiskStore::open(&path.into_path()).unwrap());
        // Create a `BeaconChain` object to pass to `Service`
        let validator_count = 1;
        let genesis_time = 13371337;

        let log = get_logger();
        let spec = MinimalEthSpec::default_spec();

        let genesis_state = interop_genesis_state(
            &generate_deterministic_keypairs(validator_count),
            genesis_time,
            &spec,
        )
        .expect("should create interop genesis state");
        let chain = BeaconChainBuilder::new(MinimalEthSpec)
            .logger(log.clone())
            .store(store.clone())
            .store_migrator(NullMigrator)
            .genesis_state(genesis_state)
            .expect("should build state using recent genesis")
            .dummy_eth1_backend()
            .expect("should build the dummy eth1 backend")
            .null_event_handler()
            .testing_slot_clock(std::time::Duration::from_secs(1))
            .expect("should configure testing slot clock")
            .reduced_tree_fork_choice()
            .expect("should add fork choice to builder")
            .build()
            .expect("should build");

        let beacon_chain = Arc::new(chain);
        let enr1 = Enr::from_str("enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8").unwrap();
        let enr2 = Enr::from_str("enr:-IS4QJ2d11eu6dC7E7LoXeLMgMP3kom1u3SE8esFSWvaHoo0dP1jg8O3-nx9ht-EO3CmG7L6OkHcMmoIh00IYWB92QABgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQIB_c-jQMOXsbjWkbN-Oj99H57gfId5pfb4wa1qxwV4CIN1ZHCCIyk").unwrap();
        let enrs = vec![enr1, enr2];

        let runtime = Runtime::new().unwrap();
        let executor = runtime.executor();

        let mut config = NetworkConfig::default();
        config.boot_nodes = enrs.clone();
        runtime
            .block_on_all(
                // Create a new network service which implicitly gets dropped at the
                // end of the block.
                Service::new(beacon_chain.clone(), &config, &executor, log.clone())
                    .into_future()
                    .and_then(move |(_service, _)| Ok(())),
            )
            .unwrap();

        // Load the persisted dht from the store
        let persisted_enrs = load_dht::<
            beacon_chain::builder::Witness<
                SimpleDiskStore<types::eth_spec::MinimalEthSpec>,
                store::migrate::NullMigrator,
                TestingSlotClock,
                beacon_chain::eth1_chain::CachingEth1Backend<
                    types::eth_spec::MinimalEthSpec,
                    SimpleDiskStore<types::eth_spec::MinimalEthSpec>,
                >,
                types::eth_spec::MinimalEthSpec,
                beacon_chain::events::NullEventHandler<types::eth_spec::MinimalEthSpec>,
            >,
        >(store);
        assert!(
            persisted_enrs.contains(&enrs[0]),
            "should have persisted the first ENR to store"
        );
        assert!(
            persisted_enrs.contains(&enrs[1]),
            "should have persisted the second ENR to store"
        );
    }
}
