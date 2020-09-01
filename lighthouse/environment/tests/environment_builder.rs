#![cfg(test)]

use environment::EnvironmentBuilder;
use eth2_testnet_config::Eth2TestnetConfig;
use std::path::PathBuf;
use types::{Epoch, MainnetEthSpec, YamlConfig};

fn builder() -> EnvironmentBuilder<MainnetEthSpec> {
    EnvironmentBuilder::mainnet()
        .single_thread_tokio_runtime()
        .expect("should set runtime")
        .null_logger()
        .expect("should set logger")
}

fn eth2_testnet_config() -> Option<Eth2TestnetConfig<MainnetEthSpec>> {
    Eth2TestnetConfig::hard_coded_default().expect("should decode hard_coded params")
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
                environment.eth2_config.spec.far_future_epoch,
                Epoch::new(999) // see testnet_dir/config.yaml
            );
        }
    }
}
