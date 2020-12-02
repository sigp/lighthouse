#![cfg(test)]

use environment::EnvironmentBuilder;
use eth2_network_config::{Eth2NetworkConfig, DEFAULT_HARDCODED_NETWORK};
use std::path::PathBuf;
use types::{V012LegacyEthSpec, YamlConfig};

fn builder() -> EnvironmentBuilder<V012LegacyEthSpec> {
    EnvironmentBuilder::v012_legacy()
        .multi_threaded_tokio_runtime()
        .expect("should set runtime")
        .null_logger()
        .expect("should set logger")
}

fn eth2_network_config() -> Option<Eth2NetworkConfig> {
    Eth2NetworkConfig::constant(DEFAULT_HARDCODED_NETWORK).expect("should decode mainnet params")
}

mod setup_eth2_config {
    use super::*;

    #[test]
    fn update_spec_with_yaml_config() {
        if let Some(mut eth2_network_config) = eth2_network_config() {
            let config_yaml = PathBuf::from("./tests/testnet_dir/config.yaml");

            eth2_network_config.yaml_config = Some(
                YamlConfig::from_file(config_yaml.as_path()).expect("should load yaml config"),
            );

            let environment = builder()
                .eth2_network_config(eth2_network_config)
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
