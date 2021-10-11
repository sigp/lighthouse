use tempfile::tempdir;

use beacon_chain::{
    store::{errors::Error, HotColdDB, LevelDB, StoreConfig},
    test_utils::test_spec,
};
use clap::{App, Arg, ArgMatches};
use environment::Environment;
use logging::test_logger;
use types::EthSpec;

pub const CMD: &str = "database_manager";
//pub const SECRETS_DIR_FLAG: &str = "secrets-dir";
//pub const VALIDATOR_DIR_FLAG: &str = "validator-dir";
//pub const WALLETS_DIR_FLAG: &str = "wallets-dir";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .visible_aliases(&["db"])
        .setting(clap::AppSettings::ColoredHelp)
        .about("Manages database")
        .arg(
            Arg::with_name("downgrade")
                .long("downgrade")
                .help("Downgrade the current database to previous version."),
        )
        .arg(
            Arg::with_name("version")
                .long("version")
                .short("v")
                .help("Display database version."),
        )
}

pub fn display_db_version<E: EthSpec>(
    _matches: &ArgMatches,
    _env: Environment<E>,
) -> Result<(), Error> {
    // Initialize parameters for open_as_is
    let spec = test_spec::<E>();
    let db_path = tempdir().unwrap();
    let hot_path = db_path.path().join("hot_db");
    let cold_path = db_path.path().join("cold_db");
    let config = StoreConfig::default();
    let log = test_logger();

    let (_db, schema_version) = HotColdDB::<E, LevelDB<E>, LevelDB<E>>::open_as_is(
        hot_path.as_path(),
        cold_path.as_path(),
        config,
        spec,
        log,
    )?;

    println!("database version: {:?}", schema_version);

    Ok(())
}

/// Run the account manager, returning an error string if the operation did not succeed.
pub fn run<T: EthSpec>(matches: &ArgMatches<'_>, env: Environment<T>) -> Result<(), String> {
    if matches.is_present("version") {
        display_db_version(matches, env).map_err(|e| format!("{:?}", e))
    } else {
        // How to display name of program and subcommand something
        // like `format!("{} {} --help", program, subcommand)`
        Err("Unknown parameter, for help `lighthouse database_manager --help`".into())
    }
}
