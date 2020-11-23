#![cfg(test)]

use environment::EnvironmentBuilder;
use eth2_testnet_config::{Eth2TestnetConfig, DEFAULT_HARDCODED_TESTNET};
use std::path::PathBuf;
use types::{V012LegacyEthSpec, YamlConfig};

fn builder() -> EnvironmentBuilder<V012LegacyEthSpec> {
    EnvironmentBuilder::v012_legacy()
        .single_thread_tokio_runtime()
        .expect("should set runtime")
        .null_logger()
        .expect("should set logger")
}

fn eth2_testnet_config() -> Option<Eth2TestnetConfig> {
    Eth2TestnetConfig::constant(DEFAULT_HARDCODED_TESTNET).expect("should decode mainnet params")
}

mod setup_eth2_config {
    use super::*;

    #[test]
    fn update_spec_with_yaml_config() {
        if let Some(mut eth2_testnet_config) = eth2_testnet_config() {
            let config_yaml = PathBuf::from("./tests/testnet_dir/config.yaml");

            eth2_testnet_config.yaml_config = Some(
                YamlConfig::from_file(config_yaml.as_path()).expect("should load yaml config"),
            );

            let environment = builder()
                .eth2_testnet_config(eth2_testnet_config)
                .expect("should setup eth2_config")
                .build()
                .expect("should build environment");

            assert_eq!(
                environment.eth2_config.spec.max_committees_per_slot,
                128 // see testnet_dir/config.yaml
            );
        }
    }
}
