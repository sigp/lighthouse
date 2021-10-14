use tempfile::tempdir;

use beacon_chain::{
    builder::Witness,
    eth1_chain::CachingEth1Backend,
    schema_change::migrate_schema,
    slot_clock::SystemTimeSlotClock,
    store::{errors::Error, metadata::SchemaVersion, HotColdDB, LevelDB, StoreConfig},
    test_utils::test_spec,
};
use clap::{App, Arg, ArgMatches};
use environment::Environment;
use logging::{a_logger, test_logger};
use types::EthSpec;

pub const CMD: &str = "database_manager";
//pub const SECRETS_DIR_FLAG: &str = "secrets-dir";
//pub const VALIDATOR_DIR_FLAG: &str = "validator-dir";
//pub const WALLETS_DIR_FLAG: &str = "wallets-dir";

pub fn downgrade_cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("downgrade")
        .visible_aliases(&["dg"])
        .setting(clap::AppSettings::ColoredHelp)
        .about("Dowgrade database")
        .help("Downgrade the current database to the previous version.")
}

pub fn version_cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("version")
        .visible_aliases(&["v"])
        .setting(clap::AppSettings::ColoredHelp)
        .about("Display database version")
        .help("Display database version")
}

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .visible_aliases(&["db"])
        .setting(clap::AppSettings::ColoredHelp)
        .about("Manages database")
        .arg(
            // Duplicate in beacon_node/src/cli.rs
            Arg::with_name("slots-per-restore-point")
                .long("slots-per-restore-point")
                .value_name("SLOT_COUNT")
                .help(
                    "Specifies how often a freezer DB restore point should be stored. \
                       Cannot be changed after initialization. \
                       [default: 2048 (mainnet) or 64 (minimal)]",
                )
                .takes_value(true),
        )
        .arg(
            // Duplicate in beacon_node/src/cli.rs
            Arg::with_name("freezer-dir")
                .long("freezer-dir")
                .value_name("DIR")
                .help("Data directory for the freezer database.")
                .takes_value(true),
        )
        .subcommand(downgrade_cli_app())
        .subcommand(version_cli_app())
}

fn get_store_config<E: EthSpec>(
    _matches: &ArgMatches,
    _env: Environment<E>,
) -> Result<StoreConfig, Error> {
    let sc = StoreConfig {
        ..StoreConfig::default()
    };

    Ok(sc)
}

pub fn display_db_version<E: EthSpec>(
    matches: &ArgMatches,
    env: Environment<E>,
) -> Result<(), Error> {
    // Initialize parameters for open_as_is
    let spec = test_spec::<E>();
    let db_path = tempdir().unwrap();
    let hot_path = db_path.path().join("hot_db");
    let cold_path = db_path.path().join("cold_db");
    let config = get_store_config(matches, env)?;
    let log = test_logger();

    let (_db, schema_version) = HotColdDB::<E, LevelDB<E>, LevelDB<E>>::open_as_is(
        hot_path.as_path(),
        cold_path.as_path(),
        config,
        spec,
        log,
    )?;

    println!("database version: {}", schema_version.0);

    Ok(())
}

pub fn downgrade_db<E: EthSpec>(matches: &ArgMatches, env: Environment<E>) -> Result<(), Error> {
    // Initialize parameters for open_as_is
    let spec = test_spec::<E>();
    let datadir = tempdir().unwrap();
    let hot_path = datadir.path().join("hot_db");
    let cold_path = datadir.path().join("cold_db");
    let config = get_store_config(matches, env)?;
    let log = a_logger(sloggers::types::Severity::Info);

    let (_db, schema_version) = HotColdDB::<E, LevelDB<E>, LevelDB<E>>::open_as_is(
        hot_path.as_path(),
        cold_path.as_path(),
        config,
        spec,
        log,
    )?;

    let from = schema_version;
    let to = SchemaVersion(from.0 - 1);
    //let to = SchemaVersion(from.0);

    println!("downgrade database version {} to {}", from.0, to.0);

    migrate_schema::<Witness<SystemTimeSlotClock, CachingEth1Backend<E>, _, _, _>>(
        _db,
        datadir.path(),
        from,
        to,
    )?;

    Ok(())
}

/// Run the database manager, returning an error string if the operation did not succeed.
pub fn run<T: EthSpec>(matches: &ArgMatches<'_>, env: Environment<T>) -> Result<(), String> {
    //println!("database_manager::run: matches:\n{:#?}", matches);
    match matches.subcommand() {
        ("version", Some(matches)) => {
            display_db_version(matches, env).map_err(|e| format!("{:?}", e))
        }
        ("downgrade", Some(matches)) => downgrade_db(matches, env).map_err(|e| format!("{:?}", e)),
        _ => Err("Unknown parameter, for help `lighthouse database_manager --help`".into()),
    }
}
