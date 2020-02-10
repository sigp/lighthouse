/*
#[cfg(test)]
mod tests {
    use super::*;
    use beacon_chain::builder::BeaconChainBuilder;
    use eth2_libp2p::Enr;
    use genesis::{generate_deterministic_keypairs, interop_genesis_state};
    use slog::Logger;
    use sloggers::{null::NullLoggerBuilder, Build};
    use std::str::FromStr;
    use store::{migrate::NullMigrator, SimpleDiskStore};
    use tokio::runtime::Runtime;
    use types::{EthSpec, MinimalEthSpec};

    fn get_logger() -> Logger {
        let builder = NullLoggerBuilder;
        builder.build().expect("should build logger")
    }

    #[test]
    fn test_dht_persistence() {
        // Create new LevelDB store
        let path = "/tmp";
        let store = Arc::new(SimpleDiskStore::open(&std::path::PathBuf::from(path)).unwrap());
        // Create a `BeaconChain` object to pass to `Service`
        let validator_count = 8;
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
            .store(store)
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

        // Create new network service
        let (service, _) = Service::new(
            beacon_chain.clone(),
            &NetworkConfig::default(),
            &runtime.executor(),
            log.clone(),
        )
        .unwrap();

        // Add enrs manually to dht
        for enr in enrs.iter() {
            service.libp2p_service.swarm.add_enr(enr.clone());
        }
        assert_eq!(
            enrs.len(),
            service
                .libp2p_service()
                .swarm
                .enr_entries()
                .collect::<Vec<_>>()
                .len(),
            "DHT should have 2 enrs"
        );
        // Drop the service value
        std::mem::drop(service);

        // Recover the network service from beacon chain store and fresh network config
        let (recovered_service, _) = Service::new(
            beacon_chain,
            &NetworkConfig::default(),
            &runtime.executor(),
            log.clone(),
        )
        .unwrap();
        assert_eq!(
            enrs.len(),
            recovered_service
                .libp2p_service()
                .lock()
                .swarm
                .enr_entries()
                .collect::<Vec<_>>()
                .len(),
            "Recovered DHT should have 2 enrs"
        );
    }
}
*/
