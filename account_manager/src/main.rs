use bls::Keypair;
use clap::{App, Arg, SubCommand};
use slog::{debug, info, o, Drain};
use std::path::PathBuf;
use types::test_utils::generate_deterministic_keypair;
use validator_client::Config as ValidatorClientConfig;

fn main() {
    // Logging
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let log = slog::Logger::root(drain, o!());

    // CLI
    let matches = App::new("Lighthouse Accounts Manager")
        .version("0.0.1")
        .author("Sigma Prime <contact@sigmaprime.io>")
        .about("Eth 2.0 Accounts Manager")
        .arg(
            Arg::with_name("datadir")
                .long("datadir")
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
                    Arg::with_name("end validator index")
                        .long("end_index")
                        .short("j")
                        .value_name("end_index")
                        .help("If supplied along with `index`, generates a range of keys.")
                        .takes_value(true),
                ),
        )
        .get_matches();

    let config = ValidatorClientConfig::parse_args(&matches, &log)
        .expect("Unable to build a configuration for the account manager.");

    // Log configuration
    info!(log, "";
          "data_dir" => &config.data_dir.to_str());

    match matches.subcommand() {
        ("generate", Some(_)) => generate_random(&config, &log),
        ("generate_deterministic", Some(m)) => {
            if let Some(string) = m.value_of("validator index") {
                let i: usize = string.parse().expect("Invalid validator index");
                if let Some(string) = m.value_of("end validator index") {
                    let j: usize = string.parse().expect("Invalid end validator index");

                    let indices: Vec<usize> = (i..j).collect();
                    generate_deterministic_multiple(&indices, &config, &log)
                } else {
                    generate_deterministic(i, &config, &log)
                }
            }
        }
        _ => panic!(
            "The account manager must be run with a subcommand. See help for more information."
        ),
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
