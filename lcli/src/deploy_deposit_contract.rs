use clap::ArgMatches;
use environment::Environment;
use eth1_test_rig::DepositContract;
use eth2_testnet_config::Eth2TestnetConfig;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use types::{ChainSpec, EthSpec, YamlConfig};
use web3::{transports::Http, Web3};

pub const SECONDS_PER_ETH1_BLOCK: u64 = 15;

pub fn run<T: EthSpec>(mut env: Environment<T>, matches: &ArgMatches) -> Result<(), String> {
    let min_genesis_time = matches
        .value_of("min-genesis-time")
        .ok_or_else(|| "min_genesis_time not specified")?
        .parse::<u64>()
        .map_err(|e| format!("Failed to parse min_genesis_time: {}", e))?;

    let min_genesis_active_validator_count = matches
        .value_of("min-genesis-active-validator-count")
        .ok_or_else(|| "min-genesis-active-validator-count not specified")?
        .parse::<u64>()
        .map_err(|e| format!("Failed to parse min-genesis-active-validator-count: {}", e))?;

    let confirmations = matches
        .value_of("confirmations")
        .ok_or_else(|| "Confirmations not specified")?
        .parse::<usize>()
        .map_err(|e| format!("Failed to parse confirmations: {}", e))?;

    let output_dir = matches
        .value_of("output")
        .ok_or_else(|| ())
        .and_then(|output| output.parse::<PathBuf>().map_err(|_| ()))
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .map(|home| home.join(".lighthouse").join("testnet"))
                .expect("should locate home directory")
        });

    let password = parse_password(matches)?;

    let endpoint = matches
        .value_of("eth1-endpoint")
        .ok_or_else(|| "eth1-endpoint not specified")?;

    let (_event_loop, transport) = Http::new(&endpoint).map_err(|e| {
        format!(
            "Failed to start HTTP transport connected to ganache: {:?}",
            e
        )
    })?;
    let web3 = Web3::new(transport);

    if output_dir.exists() {
        return Err("Output directory already exists".to_string());
    }

    // It's unlikely that this will be the _actual_ deployment block, however it'll be close
    // enough to serve our purposes.
    //
    // We only need the deposit block to put a lower bound on the block number we need to search
    // for deposit logs.
    let deploy_block = env
        .runtime()
        .block_on(web3.eth().block_number())
        .map_err(|e| format!("Failed to get block number: {}", e))?;

    info!("Present eth1 block number is {}", deploy_block);

    info!("Deploying the bytecode at https://github.com/sigp/unsafe-eth2-deposit-contract",);

    info!(
        "Submitting deployment transaction, waiting for {} confirmations",
        confirmations
    );

    let deposit_contract = env
        .runtime()
        .block_on(DepositContract::deploy_testnet(
            web3,
            confirmations,
            password,
        ))
        .map_err(|e| format!("Failed to deploy contract: {}", e))?;

    info!(
        "Deposit contract deployed. address: {}, min_genesis_time: {}, deploy_block: {}",
        deposit_contract.address(),
        min_genesis_time,
        deploy_block
    );

    info!("Writing config to {:?}", output_dir);

    let mut spec = lighthouse_testnet_spec(env.core_context().eth2_config.spec.clone());
    spec.min_genesis_time = min_genesis_time;
    spec.min_genesis_active_validator_count = min_genesis_active_validator_count;

    let testnet_config: Eth2TestnetConfig<T> = Eth2TestnetConfig {
        deposit_contract_address: format!("{}", deposit_contract.address()),
        deposit_contract_deploy_block: deploy_block.as_u64(),
        boot_enr: None,
        genesis_state: None,
        yaml_config: Some(YamlConfig::from_spec::<T>(&spec)),
    };

    testnet_config.write_to_file(output_dir)?;

    Ok(())
}

/// Modfies the specification to better suit present-capacity testnets.
pub fn lighthouse_testnet_spec(mut spec: ChainSpec) -> ChainSpec {
    spec.min_deposit_amount = 100;
    spec.max_effective_balance = 3_200_000_000;
    spec.ejection_balance = 1_600_000_000;
    spec.effective_balance_increment = 100_000_000;

    spec.eth1_follow_distance = 16;

    // This value must be at least 2x the `ETH1_FOLLOW_DISTANCE` otherwise `all_eth1_data` can
    // become a subset of `new_eth1_data` which may result in an Exception in the spec
    // implementation.
    //
    // This value determines the delay between the eth1 block that triggers genesis and the first
    // slot of that new chain.
    //
    // With a follow distance of 16, this is 40mins.
    spec.seconds_per_day = SECONDS_PER_ETH1_BLOCK * spec.eth1_follow_distance * 2 * 5;

    spec
}

pub fn parse_password(matches: &ArgMatches) -> Result<Option<String>, String> {
    if let Some(password_path) = matches.value_of("password") {
        Ok(Some(
            File::open(password_path)
                .map_err(|e| format!("Unable to open password file: {:?}", e))
                .and_then(|mut file| {
                    let mut password = String::new();
                    file.read_to_string(&mut password)
                        .map_err(|e| format!("Unable to read password file to string: {:?}", e))
                        .map(|_| password)
                })
                .map(|password| {
                    // Trim the linefeed from the end.
                    if password.ends_with("\n") {
                        password[0..password.len() - 1].to_string()
                    } else {
                        password
                    }
                })?,
        ))
    } else {
        Ok(None)
    }
}
