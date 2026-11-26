#![cfg(test)]

use environment::EnvironmentBuilder;
use eth2_network_config::{Eth2NetworkConfig, GenesisStateSource};
use types::{Config, EthSpec, Spec};

fn builder() -> EnvironmentBuilder<Spec> {
    EnvironmentBuilder::new()
        .multi_threaded_tokio_runtime()
        .expect("should set runtime")
}

fn eth2_network_config() -> Eth2NetworkConfig {
    let mut spec = Spec::default_spec();
    spec.min_genesis_active_validator_count = 100000;
    spec.inactivity_score_bias = 2;

    Eth2NetworkConfig {
        deposit_contract_deploy_block: 0,
        boot_enr: None,
        genesis_state_source: GenesisStateSource::Unknown,
        genesis_state_bytes: None,
        config: Config::from_chain_spec::<Spec>(&spec),
        kzg_trusted_setup: vec![],
    }
}

mod setup_eth2_config {
    use super::*;

    #[test]
    fn update_spec_with_network_config() {
        let environment = builder()
            .eth2_network_config(eth2_network_config())
            .expect("should setup eth2_config")
            .build()
            .expect("should build environment");

        assert_eq!(
            environment
                .eth2_config
                .spec
                .min_genesis_active_validator_count,
            100000
        );
        assert_eq!(environment.eth2_config.spec.inactivity_score_bias, 2);
    }
}
