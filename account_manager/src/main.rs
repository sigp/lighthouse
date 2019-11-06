use bls::Keypair;
use clap::{App, Arg, SubCommand};
use slog::{crit, debug, info, o, Drain};
use std::fs;
use std::path::PathBuf;
use types::test_utils::generate_deterministic_keypair;
use types::DepositData;
use validator_client::Config as ValidatorClientConfig;
mod deposit;
pub mod keystore;
pub const DEFAULT_DATA_DIR: &str = ".lighthouse-validator";
pub const CLIENT_CONFIG_FILENAME: &str = "account-manager.toml";

fn main() {
    // Logging
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let mut log = slog::Logger::root(drain, o!());

    // CLI
    let matches = App::new("Lighthouse Accounts Manager")
        .version("0.0.1")
        .author("Sigma Prime <contact@sigmaprime.io>")
        .about("Eth 2.0 Accounts Manager")
        .arg(
            Arg::with_name("logfile")
                .long("logfile")
                .value_name("logfile")
                .help("File path where output will be written.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("datadir")
                .long("datadir")
                .short("d")
                .value_name("DIR")
                .help("Data directory for keys and databases.")
                .takes_value(true),
        )
        .subcommand(
            SubCommand::with_name("generate")
                .about("Generates a new validator private key")
                .version("0.0.1")
                .author("Sigma Prime <contact@sigmaprime.io>"),
        )
        .subcommand(
            SubCommand::with_name("generate_deterministic")
                .about("Generates a deterministic validator private key FOR TESTING")
                .version("0.0.1")
                .author("Sigma Prime <contact@sigmaprime.io>")
                .arg(
                    Arg::with_name("validator index")
                        .long("index")
                        .short("i")
                        .value_name("index")
                        .help("The index of the validator, for which the test key is generated")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("validator count")
                        .long("validator_count")
                        .short("n")
                        .value_name("validator_count")
                        .help("If supplied along with `index`, generates keys `i..i + n`.")
                        .takes_value(true)
                        .default_value("1"),
                ),
        )
        .subcommand(
            SubCommand::with_name("generate_deposit_params")
                .about("Generates deposit parameters for submitting to the deposit contract")
                .version("0.0.1")
                .author("Sigma Prime <contact@sigmaprime.io>")
                .arg(
                    Arg::with_name("validator_sk_path")
                        .long("validator_sk_path")
                        .short("v")
                        .value_name("validator_sk_path")
                        .help("Path to the validator private key directory")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("withdrawal_sk_path")
                        .long("withdrawal_sk_path")
                        .short("w")
                        .value_name("withdrawal_sk_path")
                        .help("Path to the withdrawal private key directory")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("deposit_amount")
                        .long("deposit_amount")
                        .short("a")
                        .value_name("deposit_amount")
                        .help("Deposit amount in GWEI")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .get_matches();

    let data_dir = match matches
        .value_of("datadir")
        .and_then(|v| Some(PathBuf::from(v)))
    {
        Some(v) => v,
        None => {
            // use the default
            let mut default_dir = match dirs::home_dir() {
                Some(v) => v,
                None => {
                    crit!(log, "Failed to find a home directory");
                    return;
                }
            };
            default_dir.push(DEFAULT_DATA_DIR);
            default_dir
        }
    };

    // create the directory if needed
    match fs::create_dir_all(&data_dir) {
        Ok(_) => {}
        Err(e) => {
            crit!(log, "Failed to initialize data dir"; "error" => format!("{}", e));
            return;
        }
    }

    let mut client_config = ValidatorClientConfig::default();

    // Ensure the `data_dir` in the config matches that supplied to the CLI.
    client_config.data_dir = data_dir.clone();

    if let Err(e) = client_config.apply_cli_args(&matches, &mut log) {
        crit!(log, "Failed to parse ClientConfig CLI arguments"; "error" => format!("{:?}", e));
        return;
    };

    // Log configuration
    info!(log, "";
          "data_dir" => &client_config.data_dir.to_str());

    match matches.subcommand() {
        ("generate", Some(_)) => generate_random(&client_config, &log),
        ("generate_deterministic", Some(m)) => {
            if let Some(string) = m.value_of("validator index") {
                let i: usize = string.parse().expect("Invalid validator index");
                if let Some(string) = m.value_of("validator count") {
                    let n: usize = string.parse().expect("Invalid end validator count");

                    let indices: Vec<usize> = (i..i + n).collect();
                    generate_deterministic_multiple(&indices, &client_config, &log)
                } else {
                    generate_deterministic(i, &client_config, &log)
                }
            }
        }
        ("generate_deposit_params", Some(m)) => {
            let validator_kp_path = m
                .value_of("validator_sk_path")
                .expect("generating deposit params requires validator key path")
                .parse::<PathBuf>()
                .expect("Must be a valid path");
            let withdrawal_kp_path = m
                .value_of("withdrawal_sk_path")
                .expect("generating deposit params requires withdrawal key path")
                .parse::<PathBuf>()
                .expect("Must be a valid path");
            let amount = m
                .value_of("deposit_amount")
                .expect("generating deposit params requires deposit amount")
                .parse::<u64>()
                .expect("Must be a valid u64");
            let deposit = generate_deposit_params(
                validator_kp_path,
                withdrawal_kp_path,
                amount,
                &client_config,
                &log,
            );
            // TODO: just printing for now. Decide how to process
            println!("Deposit data: {:?}", deposit);
        }
        _ => {
            crit!(
                log,
                "The account manager must be run with a subcommand. See help for more information."
            );
        }
    }
}

fn generate_random(config: &ValidatorClientConfig, log: &slog::Logger) {
    save_key(&Keypair::random(), config, log)
}

fn generate_deterministic_multiple(
    validator_indices: &[usize],
    config: &ValidatorClientConfig,
    log: &slog::Logger,
) {
    for validator_index in validator_indices {
        generate_deterministic(*validator_index, config, log)
    }
}

fn generate_deterministic(
    validator_index: usize,
    config: &ValidatorClientConfig,
    log: &slog::Logger,
) {
    save_key(
        &generate_deterministic_keypair(validator_index),
        config,
        log,
    )
}

fn save_key(keypair: &Keypair, config: &ValidatorClientConfig, log: &slog::Logger) {
    let key_path: PathBuf = config
        .save_key(&keypair)
        .expect("Unable to save newly generated private key.");
    debug!(
        log,
        "Keypair generated {:?}, saved to: {:?}",
        keypair.identifier(),
        key_path.to_string_lossy()
    );
}

fn generate_deposit_params(
    vk_path: PathBuf,
    wk_path: PathBuf,
    amount: u64,
    config: &ValidatorClientConfig,
    log: &slog::Logger,
) -> DepositData {
    let vk: Keypair = config.read_keypair_file(vk_path).unwrap();
    let wk: Keypair = config.read_keypair_file(wk_path).unwrap();

    let spec = types::ChainSpec::default();
    debug!(log, "Generating deposit parameters");
    deposit::generate_deposit_params(vk, &wk, amount, &spec)
}
