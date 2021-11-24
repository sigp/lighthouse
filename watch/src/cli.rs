use crate::{
    database::{Config, Database},
    server, update_service,
};
use clap::{App, Arg};
use tokio::sync::oneshot;
use types::MainnetEthSpec;

pub const SERVE: &'static str = "serve";
pub const START_DAEMON: &'static str = "start-daemon";
pub const INIT_DB: &'static str = "init-db";
pub const CONFIG: &'static str = "config";
pub const DEFAULT_CONFIG: &'static str = "default-config";
pub const DROP: &'static str = "drop";

fn init_db<'a, 'b>() -> App<'a, 'b> {
    App::new(INIT_DB)
        .setting(clap::AppSettings::ColoredHelp)
        .arg(
            Arg::with_name(DROP)
                .long(DROP)
                .help("Drop the database before creating. DESTRUCTIVE ACTION."),
        )
}

fn start_daemon<'a, 'b>() -> App<'a, 'b> {
    App::new(START_DAEMON).setting(clap::AppSettings::ColoredHelp)
}

fn serve<'a, 'b>() -> App<'a, 'b> {
    App::new(SERVE).setting(clap::AppSettings::ColoredHelp)
}

pub fn app<'a, 'b>() -> App<'a, 'b> {
    App::new("beacon_watch_daemon")
        .author("Sigma Prime <contact@sigmaprime.io>")
        .setting(clap::AppSettings::ColoredHelp)
        .arg(
            Arg::with_name(CONFIG)
                .long(CONFIG)
                .value_name("PATH_TO_CONFIG")
                .help("Path to configuration file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name(DEFAULT_CONFIG)
                .long(DEFAULT_CONFIG)
                .help("Load a default configuration. Used only for testing.")
                .conflicts_with("config"),
        )
        .subcommand(init_db())
        .subcommand(start_daemon())
        .subcommand(serve())
}

pub async fn run() -> Result<(), String> {
    let matches = app().get_matches();

    let mut config = if matches.is_present(DEFAULT_CONFIG) {
        Config::default()
    } else {
        unimplemented!("parsing config from a file");
    };

    match matches.subcommand() {
        (INIT_DB, Some(submatches)) => {
            if submatches.is_present(DROP) {
                config.drop_dbname = true;
            }

            Database::create(&config)
                .await
                .map_err(|e| format!("Failure: {:?}", e))
                .map(|_| ())
        }
        (START_DAEMON, Some(_)) => update_service::run_once::<MainnetEthSpec>(&config)
            .await
            .map_err(|e| format!("Failure: {:?}", e)),
        (SERVE, Some(_)) => {
            let (_shutdown_tx, shutdown_rx) = oneshot::channel();
            server::serve::<MainnetEthSpec>(config, shutdown_rx)
                .await
                .map_err(|e| format!("Failure: {:?}", e))
        }
        _ => Err("Unsupported subcommand. See --help".into()),
    }
}
