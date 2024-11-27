use crate::{config::Config, logger, server, updater};
use clap::{Arg, ArgAction, Command};
use clap_utils::get_color_style;

pub const SERVE: &str = "serve";
pub const RUN_UPDATER: &str = "run-updater";
pub const CONFIG: &str = "config";

fn run_updater() -> Command {
    Command::new(RUN_UPDATER).styles(get_color_style())
}

fn serve() -> Command {
    Command::new(SERVE).styles(get_color_style())
}

pub fn app() -> Command {
    Command::new("beacon_watch_daemon")
        .author("Sigma Prime <contact@sigmaprime.io>")
        .styles(get_color_style())
        .arg(
            Arg::new(CONFIG)
                .long(CONFIG)
                .value_name("PATH_TO_CONFIG")
                .help("Path to configuration file")
                .action(ArgAction::Set)
                .global(true),
        )
        .subcommand(run_updater())
        .subcommand(serve())
}

pub async fn run() -> Result<(), String> {
    let matches = app().get_matches();

    let config = match matches.get_one::<String>(CONFIG) {
        Some(path) => Config::load_from_file(path.to_string())?,
        None => Config::default(),
    };

    logger::init_logger(&config.log_level);

    match matches.subcommand() {
        Some((RUN_UPDATER, _)) => updater::run_updater(config)
            .await
            .map_err(|e| format!("Failure: {:?}", e)),
        Some((SERVE, _)) => server::serve(config)
            .await
            .map_err(|e| format!("Failure: {:?}", e)),
        _ => Err("Unsupported subcommand. See --help".into()),
    }
}
