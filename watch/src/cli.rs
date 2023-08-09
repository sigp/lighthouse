use crate::{config::Config, logger, server, updater};
use clap::{App, Arg};
use tokio::sync::oneshot;

pub const SERVE: &str = "serve";
pub const RUN_UPDATER: &str = "run-updater";
pub const CONFIG: &str = "config";

fn run_updater<'a, 'b>() -> App<'a, 'b> {
    App::new(RUN_UPDATER).setting(clap::AppSettings::ColoredHelp)
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
                .takes_value(true)
                .global(true),
        )
        .subcommand(run_updater())
        .subcommand(serve())
}

pub async fn run() -> Result<(), String> {
    let matches = app().get_matches();

    let config = match matches.value_of(CONFIG) {
        Some(path) => Config::load_from_file(path.to_string())?,
        None => Config::default(),
    };

    logger::init_logger(&config.log_level);

    match matches.subcommand() {
        (RUN_UPDATER, Some(_)) => updater::run_updater(config)
            .await
            .map_err(|e| format!("Failure: {:?}", e)),
        (SERVE, Some(_)) => {
            let (_shutdown_tx, shutdown_rx) = oneshot::channel();
            server::serve(config, shutdown_rx)
                .await
                .map_err(|e| format!("Failure: {:?}", e))
        }
        _ => Err("Unsupported subcommand. See --help".into()),
    }
}
