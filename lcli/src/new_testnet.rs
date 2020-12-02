use clap::ArgMatches;
use clap_utils::{
    parse_optional, parse_path_with_default_in_home_dir, parse_required, parse_ssz_optional,
};
use eth2_network_config::Eth2NetworkConfig;
use std::path::PathBuf;
use types::{Address, EthSpec, YamlConfig};

pub fn run<T: EthSpec>(matches: &ArgMatches) -> Result<(), String> {
    let testnet_dir_path = parse_path_with_default_in_home_dir(
        matches,
        "testnet-dir",
        PathBuf::from(directory::DEFAULT_ROOT_DIR).join("testnet"),
    )?;
    let deposit_contract_address: Address = parse_required(matches, "deposit-contract-address")?;
    let deposit_contract_deploy_block = parse_required(matches, "deposit-contract-deploy-block")?;

    let overwrite_files = matches.is_present("force");

    if testnet_dir_path.exists() && !overwrite_files {
        return Err(format!(
            "{:?} already exists, will not overwrite. Use --force to overwrite",
            testnet_dir_path
        ));
    }

    let mut spec = T::default_spec();

    // Update the spec value if the flag was defined. Otherwise, leave it as the default.
    macro_rules! maybe_update {
        ($flag: tt, $var: ident) => {
            if let Some(val) = parse_optional(matches, $flag)? {
                spec.$var = val
            }
        };
    }

    spec.deposit_contract_address = deposit_contract_address;

    maybe_update!("min-genesis-time", min_genesis_time);
    maybe_update!("min-deposit-amount", min_deposit_amount);
    maybe_update!(
        "min-genesis-active-validator-count",
        min_genesis_active_validator_count
    );
    maybe_update!("max-effective-balance", max_effective_balance);
    maybe_update!("effective-balance-increment", effective_balance_increment);
    maybe_update!("ejection-balance", ejection_balance);
    maybe_update!("eth1-follow-distance", eth1_follow_distance);
    maybe_update!("genesis-delay", genesis_delay);

    if let Some(v) = parse_ssz_optional(matches, "genesis-fork-version")? {
        spec.genesis_fork_version = v;
    }

    let testnet = Eth2NetworkConfig {
        deposit_contract_deploy_block,
        boot_enr: Some(vec![]),
        genesis_state_bytes: None,
        yaml_config: Some(YamlConfig::from_spec::<T>(&spec)),
    };

    testnet.write_to_file(testnet_dir_path, overwrite_files)
}
