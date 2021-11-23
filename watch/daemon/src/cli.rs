use clap::{App, Arg};

pub const START: &'static str = "start";
pub const CREATE: &'static str = "create";
pub const CONFIG: &'static str = "config";
pub const DEFAULT_CONFIG: &'static str = "default-config";
pub const DROP: &'static str = "drop";

fn create<'a, 'b>() -> App<'a, 'b> {
    App::new(CREATE)
        .setting(clap::AppSettings::ColoredHelp)
        .arg(
            Arg::with_name(DROP)
                .long(DROP)
                .help("Drop the database before creating. DESTRUCTIVE ACTION."),
        )
}

fn start<'a, 'b>() -> App<'a, 'b> {
    App::new(START).setting(clap::AppSettings::ColoredHelp)
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
        .subcommand(create())
        .subcommand(start())
}
