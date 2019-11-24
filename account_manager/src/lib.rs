mod cli;

use clap::ArgMatches;
use deposit_contract::DEPOSIT_GAS;
use environment::RuntimeContext;
use eth2_testnet::Eth2TestnetDir;
use futures::{stream::unfold, Future, IntoFuture, Stream};
use rayon::prelude::*;
use slog::{crit, error, info};
use std::fs;
use std::path::PathBuf;
use types::{ChainSpec, EthSpec};
use validator_client::validator_directory::{ValidatorDirectory, ValidatorDirectoryBuilder};
use web3::{
    transports::Http,
    types::{Address, TransactionRequest, U256},
    Web3,
};

pub use cli::cli_app;

/// Run the account manager, logging an error if the operation did not succeed.
pub fn run<T: EthSpec>(matches: &ArgMatches, context: RuntimeContext<T>) {
    let log = context.log.clone();
    match run_account_manager(matches, context) {
        Ok(()) => (),
        Err(e) => crit!(log, "Account manager failed"; "error" => e),
    }
}

/// Run the account manager, returning an error if the operation did not succeed.
fn run_account_manager<T: EthSpec>(
    matches: &ArgMatches,
    context: RuntimeContext<T>,
) -> Result<(), String> {
    let log = context.log.clone();

    let datadir = matches
        .value_of("datadir")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let mut default_dir = match dirs::home_dir() {
                Some(v) => v,
                None => {
                    panic!("Failed to find a home directory");
                }
            };
            default_dir.push(".lighthouse");
            default_dir.push("validators");
            default_dir
        });

    fs::create_dir_all(&datadir).map_err(|e| format!("Failed to initialize datadir: {}", e))?;

    info!(
        log,
        "Located data directory";
        "path" => format!("{:?}", datadir)
    );

    match matches.subcommand() {
        ("validator", Some(matches)) => match matches.subcommand() {
            ("new", Some(matches)) => run_new_validator_subcommand(matches, datadir, context)?,
            _ => {
                return Err("Invalid 'validator new' command. See --help.".to_string());
            }
        },
        _ => {
            return Err("Invalid 'validator' command. See --help.".to_string());
        }
    }

    Ok(())
}

/// Describes the crypto key generation methods for a validator.
enum KeygenMethod {
    /// Produce an insecure "deterministic" keypair. Used only for interop and testing.
    Insecure(usize),
    /// Generate a new key from the `rand` thread random RNG.
    ThreadRandom,
}

/// Process the subcommand for creating new validators.
fn run_new_validator_subcommand<T: EthSpec>(
    matches: &ArgMatches,
    datadir: PathBuf,
    context: RuntimeContext<T>,
) -> Result<(), String> {
    let log = context.log.clone();

    let methods: Vec<KeygenMethod> = match matches.subcommand() {
        ("insecure", Some(matches)) => {
            let first = matches
                .value_of("first")
                .ok_or_else(|| "No first index".to_string())?
                .parse::<usize>()
                .map_err(|e| format!("Unable to parse first index: {}", e))?;
            let last = matches
                .value_of("last")
                .ok_or_else(|| "No last index".to_string())?
                .parse::<usize>()
                .map_err(|e| format!("Unable to parse first index: {}", e))?;

            (first..last).map(KeygenMethod::Insecure).collect()
        }
        ("random", Some(matches)) => {
            let count = matches
                .value_of("validator_count")
                .ok_or_else(|| "No validator count".to_string())?
                .parse::<usize>()
                .map_err(|e| format!("Unable to parse validator count: {}", e))?;

            (0..count).map(|_| KeygenMethod::ThreadRandom).collect()
        }
        _ => {
            return Err("Invalid 'validator' command. See --help.".to_string());
        }
    };

    let validators = make_validators(datadir.clone(), &methods, &context.eth2_config.spec)?;

    if matches.is_present("send-deposits") {
        let eth1_endpoint = matches
            .value_of("eth1-endpoint")
            .ok_or_else(|| "No eth1-endpoint".to_string())?;
        let account_index = matches
            .value_of("account-index")
            .ok_or_else(|| "No account-index".to_string())?
            .parse::<usize>()
            .map_err(|e| format!("Unable to parse account-index: {}", e))?;

        let deposit_contract = if let Some(testnet_dir_str) = matches.value_of("testnet-dir") {
            let testnet_dir = testnet_dir_str
                .parse::<PathBuf>()
                .map_err(|e| format!("Unable to parse testnet-dir: {}", e))?;

            let eth2_testnet_dir = Eth2TestnetDir::load(testnet_dir)
                .map_err(|e| format!("Failed to load testnet dir: {}", e))?;

            // Convert from `types::Address` to `web3::types::Address`.
            Address::from_slice(
                eth2_testnet_dir
                    .deposit_contract_address()?
                    .as_fixed_bytes(),
            )
        } else {
            matches
                .value_of("deposit-contract")
                .ok_or_else(|| "No deposit-contract".to_string())?
                .parse::<Address>()
                .map_err(|e| format!("Unable to parse deposit-contract: {}", e))?
        };

        context.executor.spawn(deposit_validators(
            context.clone(),
            eth1_endpoint.to_string(),
            deposit_contract,
            validators.clone(),
            account_index,
        ));
    }

    info!(
        log,
        "Generated validator directories";
        "base_path" => format!("{:?}", datadir),
        "count" => validators.len(),
    );

    Ok(())
}

fn deposit_validators<E: EthSpec>(
    context: RuntimeContext<E>,
    eth1_endpoint: String,
    deposit_contract: Address,
    validators: Vec<ValidatorDirectory>,
    account_index: usize,
) -> impl Future<Item = (), Error = ()> {
    let deposit_amount = context.eth2_config.spec.max_effective_balance;
    let log = context.log.clone();

    Http::new(&eth1_endpoint)
        .map_err(|e| format!("Failed to start web3 HTTP transport: {:?}", e))
        .into_future()
        .and_then(move |(_event_loop, transport)| {
            let web3 = Web3::new(transport);

            unfold(validators.into_iter(), move |mut validators| {
                let web3 = web3.clone();

                validators.next().map(move |validator| {
                    deposit_validator(
                        web3,
                        deposit_contract,
                        &validator,
                        deposit_amount,
                        account_index,
                    )
                    .map(|()| ((), validators))
                })
            })
            .collect()
        })
        .map_err(move |e| error!(log, "Error whilst depositing validator"; "error" => e))
        .map(|_| ())
}

fn deposit_validator(
    web3: Web3<Http>,
    deposit_contract: Address,
    validator: &ValidatorDirectory,
    deposit_amount: u64,
    account_index: usize,
) -> impl Future<Item = (), Error = String> {
    let web3_1 = web3.clone();

    let deposit_data = validator
        .deposit_data
        .clone()
        .expect("Validators must have a deposit data");

    web3.eth()
        .accounts()
        .map_err(|e| format!("Failed to get accounts: {:?}", e))
        .and_then(move |accounts| {
            accounts
                .get(account_index)
                .cloned()
                .ok_or_else(|| "Insufficient accounts for deposit".to_string())
        })
        .and_then(move |from| {
            let tx_request = TransactionRequest {
                from,
                to: Some(deposit_contract),
                gas: Some(U256::from(DEPOSIT_GAS)),
                gas_price: None,
                value: Some(U256::from(deposit_amount)),
                data: Some(deposit_data.into()),
                nonce: None,
                condition: None,
            };

            web3_1
                .eth()
                .send_transaction(tx_request)
                .map_err(|e| format!("Failed to call deposit fn: {:?}", e))
        })
        .map(|_| ())
}

/// Produces a validator directory for each of the key generation methods provided in `methods`.
fn make_validators(
    datadir: PathBuf,
    methods: &[KeygenMethod],
    spec: &ChainSpec,
) -> Result<Vec<ValidatorDirectory>, String> {
    methods
        .par_iter()
        .map(|method| {
            let mut builder = ValidatorDirectoryBuilder::default()
                .spec(spec.clone())
                .full_deposit_amount()?;

            builder = match method {
                KeygenMethod::Insecure(index) => builder.insecure_keypairs(*index),
                KeygenMethod::ThreadRandom => builder.thread_random_keypairs(),
            };

            builder
                .create_directory(datadir.clone())?
                .write_keypair_files()?
                .write_eth1_data_file()?
                .build()
        })
        .collect()
}
