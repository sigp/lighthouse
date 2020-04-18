use clap::{App, Arg, ArgMatches};
use clap_utils;
use environment::Environment;
use std::fs;
use std::path::PathBuf;
use types::EthSpec;
use validator_client::validator_directory::ValidatorDirectoryBuilder;
use web3::{transports::Ipc, types::Address, Web3};

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("deposited")
        .about("Creates new Lighthouse validator keys and directories. Each newly-created validator
        will have a deposit transaction formed and submitted to the deposit contract via
        --eth1-ipc. Will only write each validator keys to disk if the deposit transaction returns
        successfully from the eth1 node. The process exits immediately if any Eth1 tx fails. Does
        not wait for Eth1 confirmation blocks, so there is no guarantee that a deposit will be
        accepted in the Eth1 chain.")
        .arg(
            Arg::with_name("validator-dir")
                .long("validator-dir")
                .value_name("VALIDATOR_DIRECTORY")
                .help("The path where the validator directories will be created. Defaults to ~/.lighthouse/validators")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("eth1-ipc")
                .long("eth1-ipc")
                .value_name("ETH1_IPC_PATH")
                .help("Path to an Eth1 JSON-RPC IPC endpoint")
                .takes_value(true)
                .required(true)
        )
        .arg(
            Arg::with_name("from-address")
                .long("from-address")
                .value_name("FROM_ETH1_ADDRESS")
                .help("The address that will submit the eth1 deposit. Must be unlocked on the node
                    at --eth1-ipc.")
                .takes_value(true)
                .required(true)
        )
        .arg(
            Arg::with_name("deposit-gwei")
                .long("deposit-gwei")
                .value_name("DEPOSIT_GWEI")
                .help("The GWEI value of the deposit amount. Defaults to the minimum amount
                    required for an active validator (MAX_EFFECTIVE_BALANCE.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("count")
                .long("count")
                .value_name("DEPOSIT_COUNT")
                .help("The number of deposits to create, regardless of how many already exist")
                .conflicts_with("limit")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("at-least")
                .long("at-least")
                .value_name("VALIDATOR_COUNT")
                .help("Observe the number of validators in --validator-dir, only creating enough to
                ensure reach the given count. Never deletes an existing validator.")
                .conflicts_with("count")
                .takes_value(true),
        )
}

pub fn cli_run<T: EthSpec>(matches: &ArgMatches, mut env: Environment<T>) -> Result<(), String> {
    let spec = env.core_context().eth2_config.spec;

    let validator_dir = clap_utils::parse_path_with_default_in_home_dir(
        matches,
        "validator_dir",
        PathBuf::new().join(".lighthouse").join("validators"),
    )?;
    let eth1_ipc_path: PathBuf = clap_utils::parse_required(matches, "eth1-ipc")?;
    let from_address: Address = clap_utils::parse_required(matches, "from-address")?;
    let deposit_gwei = clap_utils::parse_optional(matches, "deposit-gwei")?
        .unwrap_or_else(|| spec.max_effective_balance);
    let count: Option<usize> = clap_utils::parse_optional(matches, "count")?;
    let at_least: Option<usize> = clap_utils::parse_optional(matches, "at-least")?;

    let n = match (count, at_least) {
        (Some(_), Some(_)) => Err("Cannot supply --count and --at-least".to_string()),
        (None, None) => Err("Must supply either --count or --at-least".to_string()),
        (Some(count), None) => Ok(count),
        (None, Some(at_least)) => fs::read_dir(&validator_dir)
            .map(|iter| at_least.saturating_sub(iter.count()))
            .map_err(|e| format!("Unable to read {:?}: {}", validator_dir, e)),
    }?;

    let deposit_contract = env
        .testnet
        .as_ref()
        .ok_or_else(|| "Unable to run account manager without a testnet dir".to_string())?
        .deposit_contract_address()
        .map_err(|e| format!("Unable to parse deposit contract address: {}", e))?;

    if deposit_contract == Address::zero() {
        return Err("Refusing to deposit to the zero address. Check testnet configuration.".into());
    }

    let (_event_loop_handle, transport) =
        Ipc::new(eth1_ipc_path).map_err(|e| format!("Unable to connect to eth1 IPC: {:?}", e))?;
    let web3 = Web3::new(transport);

    for _ in 0..n {
        let validator = env
            .runtime()
            .block_on(
                ValidatorDirectoryBuilder::default()
                    .spec(spec.clone())
                    .custom_deposit_amount(deposit_gwei)
                    .thread_random_keypairs()
                    .submit_eth1_deposit(web3.clone(), from_address, deposit_contract),
            )?
            .create_directory(validator_dir.clone())?
            .write_keypair_files()?
            .write_eth1_data_file()?
            .build()?;

        if let Some(voting_keypair) = validator.voting_keypair {
            println!("{:?}", voting_keypair.pk)
        }
    }

    Ok(())
}
