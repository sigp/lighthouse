use bls::Keypair;
use clap::{App, Arg, SubCommand};
use slog::{debug, info, o, Drain};
use std::path::PathBuf;
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
        .get_matches();

    let config = ValidatorClientConfig::parse_args(&matches, &log)
        .expect("Unable to build a configuration for the account manager.");

    // Log configuration
    info!(log, "";
          "data_dir" => &config.data_dir.to_str());

    match matches.subcommand() {
        ("generate", Some(_gen_m)) => {
            let keypair = Keypair::random();
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
        _ => panic!(
            "The account manager must be run with a subcommand. See help for more information."
        ),
    }
}
