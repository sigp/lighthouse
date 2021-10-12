use tempfile::tempdir;

use beacon_chain::{
    store::{errors::Error, metadata::SchemaVersion, HotColdDB, LevelDB, StoreConfig},
    test_utils::test_spec,
};
use clap::{App, Arg, ArgMatches};
use environment::Environment;
use logging::test_logger;
use types::EthSpec;

//use beacon_chain::{
//    builder::Witness,
//    schema_change::migrate_schema,
//    slot_clock::SlotClock,
//    store::ItemStore,
//    BeaconChainTypes, Eth1ChainBackend,
//};

//impl<TSlotClock, TEth1Backend, TEthSpec, THotStore, TColdStore> BeaconChainTypes
//    for Witness<TSlotClock, TEth1Backend, TEthSpec, THotStore, TColdStore>
//where
//    THotStore: ItemStore<TEthSpec> + 'static,
//    TColdStore: ItemStore<TEthSpec> + 'static,
//    TSlotClock: SlotClock + 'static,
//    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
//    TEthSpec: EthSpec + 'static,
//{
//    type HotStore = THotStore;
//    type ColdStore = TColdStore;
//    type SlotClock = TSlotClock;
//    type Eth1Chain = TEth1Backend;
//    type EthSpec = TEthSpec;
//}

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
    let log = test_logger();

    let (_db, schema_version) = HotColdDB::<E, LevelDB<E>, LevelDB<E>>::open_as_is(
        hot_path.as_path(),
        cold_path.as_path(),
        config,
        spec,
        log,
    )?;

    let from = schema_version;
    let to = SchemaVersion(from.0 - 1);

    println!("downgrade database version {} to {}", from.0, to.0,);

    // Cannot figure out how to invoke migrate_schema as it's a generic function
    // that must implement the `pub trait BeaconChainTypes`. The two only places
    // where migrate_schema is called are:
    //
    //  - Recursively in the implementation itself in
    //    beacon_node/beacon_chain/src/schema_change.rs
    //
    //  - beacon_node/store/srch/hot_cold_store.rs::open where it's passed
    //    as a fn parameter in a call from
    //    beacon_node/client/src/builder.rs::disk_store

    //migrate_schema::Witness<TSlotClock, TEth1Backend, TEthSpec, THotStore, TColdStore>(_db, datadir.path(), from, to)?;
    //migrate_schema::<_>(_db, datadir.path(), from, to)?;

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
