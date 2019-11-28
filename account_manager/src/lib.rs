mod cli;

use clap::ArgMatches;
use deposit_contract::DEPOSIT_GAS;
use environment::{Environment, RuntimeContext};
use eth2_testnet::Eth2TestnetDir;
use futures::{future, stream::unfold, Future, IntoFuture, Stream};
use rayon::prelude::*;
use slog::{crit, error, info, Logger};
use std::fs;
use std::fs::File;
use std::io::Read;
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
pub fn run<T: EthSpec>(matches: &ArgMatches, mut env: Environment<T>) {
    let log = env.core_context().log.clone();
    match run_account_manager(matches, env) {
        Ok(()) => (),
        Err(e) => crit!(log, "Account manager failed"; "error" => e),
    }
}

/// Run the account manager, returning an error if the operation did not succeed.
fn run_account_manager<T: EthSpec>(
    matches: &ArgMatches,
    mut env: Environment<T>,
) -> Result<(), String> {
    let context = env.core_context();
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
            ("new", Some(matches)) => run_new_validator_subcommand(matches, datadir, env)?,
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
    mut env: Environment<T>,
) -> Result<(), String> {
    let context = env.core_context();
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

    let deposit_value = matches
        .value_of("deposit-value")
        .ok_or_else(|| "No deposit-value".to_string())?
        .parse::<u64>()
        .map_err(|e| format!("Unable to parse deposit-value: {}", e))?;

    let validators = make_validators(
        datadir.clone(),
        &methods,
        deposit_value,
        &context.eth2_config.spec,
    )?;

    if matches.is_present("send-deposits") {
        let eth1_endpoint = matches
            .value_of("eth1-endpoint")
            .ok_or_else(|| "No eth1-endpoint".to_string())?;
        let account_index = matches
            .value_of("account-index")
            .ok_or_else(|| "No account-index".to_string())?
            .parse::<usize>()
            .map_err(|e| format!("Unable to parse account-index: {}", e))?;

        let password = if let Some(password_path) = matches.value_of("password") {
            Some(
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
            )
        } else {
            None
        };

        info!(
            log,
            "Submitting validator deposits";
            "eth1_node_http_endpoint" => eth1_endpoint
        );

        let deposit_contract = if let Some(testnet_dir_str) = matches.value_of("testnet-dir") {
            let testnet_dir = testnet_dir_str
                .parse::<PathBuf>()
                .map_err(|e| format!("Unable to parse testnet-dir: {}", e))?;

            if !testnet_dir.exists() {
                return Err(format!(
                    "Testnet directory at {:?} does not exist",
                    testnet_dir
                ));
            }

            info!(
                log,
                "Loading deposit contract address";
                "testnet_dir" => format!("{:?}", &testnet_dir)
            );

            let eth2_testnet_dir: Eth2TestnetDir<T> = Eth2TestnetDir::load(testnet_dir.clone())
                .map_err(|e| format!("Failed to load testnet dir at {:?}: {}", testnet_dir, e))?;

            // Convert from `types::Address` to `web3::types::Address`.
            Address::from_slice(
                eth2_testnet_dir
                    .deposit_contract_address()?
                    .as_fixed_bytes(),
            )
        } else {
            matches
                .value_of("deposit-contract")
                .ok_or_else(|| "No --deposit-contract or --testnet-dir".to_string())?
                .parse::<Address>()
                .map_err(|e| format!("Unable to parse deposit-contract: {}", e))?
        };

        if let Err(()) = env.runtime().block_on(deposit_validators(
            context.clone(),
            eth1_endpoint.to_string(),
            deposit_contract,
            validators.clone(),
            account_index,
            deposit_value,
            password,
        )) {
            error!(
                log,
                "Created validators but could not submit deposits";
            )
        } else {
            info!(
                log,
                "Validator deposits complete";
            );
        }
    }

    info!(
        log,
        "Generated validator directories";
        "base_path" => format!("{:?}", datadir),
        "count" => validators.len(),
    );

    Ok(())
}

/// Produces a validator directory for each of the key generation methods provided in `methods`.
fn make_validators(
    datadir: PathBuf,
    methods: &[KeygenMethod],
    deposit_value: u64,
    spec: &ChainSpec,
) -> Result<Vec<ValidatorDirectory>, String> {
    methods
        .par_iter()
        .map(|method| {
            let mut builder = ValidatorDirectoryBuilder::default()
                .spec(spec.clone())
                .custom_deposit_amount(deposit_value);

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

fn deposit_validators<E: EthSpec>(
    context: RuntimeContext<E>,
    eth1_endpoint: String,
    deposit_contract: Address,
    validators: Vec<ValidatorDirectory>,
    account_index: usize,
    deposit_value: u64,
    password: Option<String>,
) -> impl Future<Item = (), Error = ()> {
    let log_1 = context.log.clone();
    let log_2 = context.log.clone();

    Http::new(&eth1_endpoint)
        .map_err(move |e| {
            error!(
                log_1,
                "Failed to start web3 HTTP transport";
                "error" => format!("{:?}", e)
            )
        })
        .into_future()
        .and_then(move |(event_loop, transport)| {
            let web3 = Web3::new(transport);

            unfold(validators.into_iter(), move |mut validators| {
                let web3 = web3.clone();
                let log = log_2.clone();
                let password = password.clone();

                validators.next().map(move |validator| {
                    deposit_validator(
                        web3,
                        deposit_contract,
                        &validator,
                        deposit_value,
                        account_index,
                        password,
                        log,
                    )
                    .map(|()| ((), validators))
                })
            })
            .collect()
            .map(|_| event_loop)
        })
        // Web3 gives errors if the event loop is dropped whilst performing requests.
        .map(|event_loop| drop(event_loop))
}

fn deposit_validator(
    web3: Web3<Http>,
    deposit_contract: Address,
    validator: &ValidatorDirectory,
    deposit_amount: u64,
    account_index: usize,
    password_opt: Option<String>,
    log: Logger,
) -> impl Future<Item = (), Error = ()> {
    let web3_1 = web3.clone();
    let web3_2 = web3.clone();

    let log_1 = log.clone();
    let log_2 = log.clone();

    let validator_voting_pubkey_1 = validator
        .voting_keypair
        .clone()
        .expect("Validators must have a voting public key")
        .pk;
    let validator_voting_pubkey_2 = validator_voting_pubkey_1.clone();

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
        .and_then(move |from_address| {
            let future: Box<dyn Future<Item = Address, Error = String> + Send> =
                if let Some(password) = password_opt {
                    // Unlock for only a single transaction.
                    let duration = None;

                    let future = web3_1
                        .personal()
                        .unlock_account(from_address, &password, duration)
                        .then(move |result| match result {
                            Ok(true) => Ok(from_address),
                            Ok(false) => Err("Eth1 node refused to unlock account".to_string()),
                            Err(e) => Err(format!("Eth1 unlock request failed: {:?}", e)),
                        });

                    Box::new(future)
                } else {
                    Box::new(future::ok(from_address))
                };

            future
        })
        .and_then(move |from| {
            let tx_request = TransactionRequest {
                from,
                to: Some(deposit_contract),
                gas: Some(U256::from(DEPOSIT_GAS)),
                gas_price: None,
                value: Some(U256::from(from_gwei(deposit_amount))),
                data: Some(deposit_data.into()),
                nonce: None,
                condition: None,
            };

            web3_2
                .eth()
                .send_transaction(tx_request)
                .map_err(|e| format!("Failed to call deposit fn: {:?}", e))
        })
        .map(move |tx| {
            info!(
                log_1,
                "Validator deposit successful";
                "eth1_tx_hash" => format!("{:?}", tx),
                "validator_voting_pubkey" => format!("{:?}", validator_voting_pubkey_1)
            )
        })
        .map_err(move |e| {
            error!(
                log_2,
                "Validator deposit_failed";
                "error" => e,
                "validator_voting_pubkey" => format!("{:?}", validator_voting_pubkey_2)
            )
        })
}

fn from_gwei(gwei: u64) -> U256 {
    U256::from(gwei) * U256::exp10(9)
}
