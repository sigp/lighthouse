#[cfg(not(debug_assertions))]
#[cfg(test)]
mod tests {
    use crate::persisted_dht::load_dht;
    use crate::{NetworkConfig, NetworkService};
    use beacon_chain::test_utils::BeaconChainHarness;
    use eth2_libp2p::Enr;
    use slog::Logger;
    use sloggers::{null::NullLoggerBuilder, Build};
    use std::str::FromStr;
    use std::sync::Arc;
    use tokio::runtime::Runtime;
    use types::{test_utils::generate_deterministic_keypairs, MinimalEthSpec};

    fn get_logger() -> Logger {
        let builder = NullLoggerBuilder;
        builder.build().expect("should build logger")
    }

    #[test]
    fn test_dht_persistence() {
        let log = get_logger();

        let beacon_chain = Arc::new(
            BeaconChainHarness::new(MinimalEthSpec, generate_deterministic_keypairs(8)).chain,
        );

        let store = beacon_chain.store.clone();

        let enr1 = Enr::from_str("enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8").unwrap();
        let enr2 = Enr::from_str("enr:-IS4QJ2d11eu6dC7E7LoXeLMgMP3kom1u3SE8esFSWvaHoo0dP1jg8O3-nx9ht-EO3CmG7L6OkHcMmoIh00IYWB92QABgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQIB_c-jQMOXsbjWkbN-Oj99H57gfId5pfb4wa1qxwV4CIN1ZHCCIyk").unwrap();
        let enrs = vec![enr1, enr2];

        let runtime = Runtime::new().unwrap();

        let (signal, exit) = exit_future::signal();
        let executor = environment::TaskExecutor::new(runtime.handle().clone(), exit, log.clone());

        let mut config = NetworkConfig::default();
        config.libp2p_port = 21212;
        config.discovery_port = 21212;
        config.boot_nodes = enrs.clone();
        runtime.spawn(async move {
            // Create a new network service which implicitly gets dropped at the
            // end of the block.

            let _ = NetworkService::start(beacon_chain.clone(), &config, executor).unwrap();
            drop(signal);
        });
        runtime.shutdown_timeout(tokio::time::Duration::from_millis(300));

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
}
