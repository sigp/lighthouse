use clap::ArgMatches;
use environment::Environment;
use eth1_test_rig::DepositContract;
use eth2_testnet::Eth2TestnetDir;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use types::EthSpec;
use web3::{transports::Http, Web3};

pub const DEFAULT_DATA_DIR: &str = ".lighthouse/testnet";

pub fn run<T: EthSpec>(mut env: Environment<T>, matches: &ArgMatches) -> Result<(), String> {
    let min_genesis_time = matches
        .value_of("min-genesis-time")
        .ok_or_else(|| "min_genesis_time not specified")?
        .parse::<u64>()
        .map_err(|e| format!("Failed to parse min_genesis_time: {}", e))?;

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
                .map(|mut home| {
                    home.push(DEFAULT_DATA_DIR);
                    home
                })
                .expect("should locate home directory")
        });

    let password = parse_password(matches)?;

    let endpoint = matches
        .value_of("endpoint")
        .ok_or_else(|| "Endpoint not specified")?;

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

    Eth2TestnetDir::new(
        output_dir,
        format!("{}", deposit_contract.address()),
        deploy_block.as_u64(),
        min_genesis_time,
    )?;

    Ok(())
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
