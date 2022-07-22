use crate::{config::Config, logger, server, updater};
use clap::{App, Arg};
use tokio::sync::oneshot;

pub const SERVE: &str = "serve";
pub const START_DAEMON: &str = "start-daemon";
pub const CONFIG: &str = "config";

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
                .takes_value(true)
                .global(true),
        )
        .subcommand(start_daemon())
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
        (START_DAEMON, Some(_)) => updater::run_once(config)
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
