use crate::helpers::*;
use clap::ArgMatches;
use eth2_testnet_config::Eth2TestnetConfig;
use std::path::PathBuf;
use types::{EthSpec, YamlConfig};

pub fn run<T: EthSpec>(matches: &ArgMatches) -> Result<(), String> {
    let testnet_dir_path = parse_path_with_default_in_home_dir(
        matches,
        "testnet-dir",
        PathBuf::from(".lighthouse/testnet"),
    )?;
    let min_genesis_time = parse_u64_opt(matches, "min-genesis-time")?;
    let min_genesis_delay = parse_u64(matches, "min-genesis-delay")?;
    let min_genesis_active_validator_count =
        parse_u64(matches, "min-genesis-active-validator-count")?;
    let min_deposit_amount = parse_u64(matches, "min-deposit-amount")?;
    let max_effective_balance = parse_u64(matches, "max-effective-balance")?;
    let effective_balance_increment = parse_u64(matches, "effective-balance-increment")?;
    let ejection_balance = parse_u64(matches, "ejection-balance")?;
    let eth1_follow_distance = parse_u64(matches, "eth1-follow-distance")?;
    let deposit_contract_deploy_block = parse_u64(matches, "deposit-contract-deploy-block")?;
    let genesis_fork_version = parse_fork_opt(matches, "genesis-fork-version")?;
    let deposit_contract_address = parse_address(matches, "deposit-contract-address")?;

    if testnet_dir_path.exists() {
        return Err(format!(
            "{:?} already exists, will not overwrite",
            testnet_dir_path
        ));
    }

    let mut spec = T::default_spec();
    if let Some(time) = min_genesis_time {
        spec.min_genesis_time = time;
    } else {
        spec.min_genesis_time = time_now()?;
    }
    spec.min_deposit_amount = min_deposit_amount;
    spec.min_genesis_active_validator_count = min_genesis_active_validator_count;
    spec.max_effective_balance = max_effective_balance;
    spec.effective_balance_increment = effective_balance_increment;
    spec.ejection_balance = ejection_balance;
    spec.eth1_follow_distance = eth1_follow_distance;
    spec.min_genesis_delay = min_genesis_delay;
    if let Some(v) = genesis_fork_version {
        spec.genesis_fork_version = v;
    }

    let testnet: Eth2TestnetConfig<T> = Eth2TestnetConfig {
        deposit_contract_address: format!("{:?}", deposit_contract_address),
        deposit_contract_deploy_block,
        boot_enr: Some(vec![]),
        genesis_state: None,
        yaml_config: Some(YamlConfig::from_spec::<T>(&spec)),
    };

    testnet.write_to_file(testnet_dir_path)
}
