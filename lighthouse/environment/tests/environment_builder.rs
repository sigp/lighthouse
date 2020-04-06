#![cfg(test)]

use clap::ArgMatches;
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

fn dummy_data_dir() -> PathBuf {
    PathBuf::from("./tests/datadir_that_does_not_exist")
}

fn eth2_testnet_config() -> Eth2TestnetConfig<MainnetEthSpec> {
    Eth2TestnetConfig::hard_coded().expect("should decode hard_coded params")
}

/*
 *
 * TODO: disabled until hardcoded testnet config is updated for v0.11
 *
mod setup_eth2_config {
    use super::*;

    #[test]
    fn returns_err_if_the_loaded_config_doesnt_match() {
        // `Minimal` spec
        let path_to_minimal_spec = PathBuf::from("./tests/minimal_spec");

        // `Mainnet` spec
        let builder = builder();

        let result = builder.setup_eth2_config(
            path_to_minimal_spec,
            eth2_testnet_config(),
            &ArgMatches::default(),
        );

        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            "Eth2 config loaded from disk does not match client spec version. Got minimal expected mainnet"
        );
    }

    #[test]
    fn update_slot_time() {
        // testnet
        let cli_args =
            beacon_node::cli_app().get_matches_from(vec!["app", "testnet", "--slot-time", "999"]);

        let environment = builder()
            .setup_eth2_config(dummy_data_dir(), eth2_testnet_config(), &cli_args)
            .expect("should setup eth2_config")
            .build()
            .expect("should build environment");

        assert_eq!(environment.eth2_config.spec.milliseconds_per_slot, 999);
    }

    #[test]
    fn update_spec_with_yaml_config() {
        let config_yaml = PathBuf::from("./tests/testnet_dir/config.yaml");

        let mut eth2_testnet_config = eth2_testnet_config();
        eth2_testnet_config.yaml_config =
            Some(YamlConfig::from_file(config_yaml.as_path()).expect("should load yaml config"));

        let environment = builder()
            .setup_eth2_config(
                dummy_data_dir(),
                eth2_testnet_config,
                &ArgMatches::default(),
            )
            .expect("should setup eth2_config")
            .build()
            .expect("should build environment");

        assert_eq!(
            environment.eth2_config.spec.far_future_epoch,
            Epoch::new(999) // see testnet_dir/config.yaml
        );
    }
}
*/
