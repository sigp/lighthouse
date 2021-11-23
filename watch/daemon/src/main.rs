use config::Config;
use database::Database;
use env_logger::Builder;
use log::error;
use std::process::exit;
use types::MainnetEthSpec;

mod cli;
mod config;
mod database;
mod start;

#[derive(Debug)]
pub enum Error {
    Postgres(tokio_postgres::Error),
    MissingParameter(&'static str),
    InvalidSlot,
    InvalidRoot,
    SensitiveUrl(eth2::SensitiveError),
    BeaconNode(eth2::Error),
    RemoteHeadUnknown,
}

impl From<tokio_postgres::Error> for Error {
    fn from(e: tokio_postgres::Error) -> Self {
        Error::Postgres(e)
    }
}

impl From<eth2::Error> for Error {
    fn from(e: eth2::Error) -> Self {
        Error::BeaconNode(e)
    }
}

#[tokio::main]
async fn main() {
    Builder::from_default_env().init();

    match run().await {
        Ok(()) => exit(0),
        Err(e) => {
            error!("Command failed: {}", e);
            eprintln!("{}", e);
            drop(e);
            exit(1)
        }
    }
}

async fn run() -> Result<(), String> {
    let matches = cli::app().get_matches();

    let mut config = if matches.is_present(cli::DEFAULT_CONFIG) {
        Config::default()
    } else {
        unimplemented!("parsing config from a file");
    };

    match matches.subcommand() {
        (cli::CREATE, Some(submatches)) => {
            if submatches.is_present(cli::DROP) {
                config.drop_dbname = true;
            }

            Database::create(config)
                .await
                .map_err(|e| format!("Failure: {:?}", e))
                .map(|_| ())
        }
        (cli::START, Some(_)) => start::start::<MainnetEthSpec>(config)
            .await
            .map_err(|e| format!("Failure: {:?}", e)),
        _ => Err("Unsupported subcommand. See --help".into()),
    }
}
