use beacon_chain::{
    builder::Witness, eth1_chain::CachingEth1Backend, schema_change::migrate_schema,
    slot_clock::SystemTimeSlotClock,
};
use beacon_node::{get_data_dir, ClientConfig};
use clap::{App, Arg, ArgMatches};
use environment::{Environment, RuntimeContext};
use slog::{info, Logger};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use store::{
    errors::Error,
    metadata::{SchemaVersion, CURRENT_SCHEMA_VERSION},
    DBColumn, HotColdDB, KeyValueStore, LevelDB,
};
use strum::{EnumString, EnumVariantNames, VariantNames};
use types::{EthSpec, VList};

pub const CMD: &str = "database_manager";

pub fn version_cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("version")
        .visible_aliases(&["v"])
        .setting(clap::AppSettings::ColoredHelp)
        .about("Display database schema version")
}

pub fn migrate_cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("migrate")
        .setting(clap::AppSettings::ColoredHelp)
        .about("Migrate the database to a specific schema version")
        .arg(
            Arg::with_name("to")
                .long("to")
                .value_name("VERSION")
                .help("Schema version to migrate to")
                .takes_value(true)
                .required(true),
        )
}

pub fn inspect_cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new("inspect")
        .setting(clap::AppSettings::ColoredHelp)
        .about("Inspect raw database values")
        .arg(
            Arg::with_name("column")
                .long("column")
                .value_name("TAG")
                .help("3-byte column ID (see `DBColumn`)")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("output")
                .long("output")
                .value_name("TARGET")
                .help("Select the type of output to show")
                .default_value("sizes")
                .possible_values(InspectTarget::VARIANTS),
        )
        .arg(
            Arg::with_name("skip")
                .long("skip")
                .value_name("N")
                .help("Skip over the first N keys"),
        )
        .arg(
            Arg::with_name("limit")
                .long("limit")
                .value_name("N")
                .help("Output at most N keys"),
        )
        .arg(
            Arg::with_name("freezer")
                .long("freezer")
                .help("Inspect the freezer DB rather than the hot DB")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("output-dir")
                .long("output-dir")
                .value_name("DIR")
                .help("Base directory for the output files. Defaults to the current directory")
                .takes_value(true),
        )
}

pub fn prune_payloads_app<'a, 'b>() -> App<'a, 'b> {
    App::new("prune_payloads")
        .setting(clap::AppSettings::ColoredHelp)
        .about("Prune finalized execution payloads")
}

pub fn diff_app<'a, 'b>() -> App<'a, 'b> {
    App::new("diff")
        .setting(clap::AppSettings::ColoredHelp)
        .about("Diff SSZ balances")
        .arg(
            Arg::with_name("first")
                .long("first")
                .value_name("PATH")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("second")
                .long("second")
                .value_name("PATH")
                .takes_value(true)
                .required(true),
        )
}

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .visible_aliases(&["db"])
        .setting(clap::AppSettings::ColoredHelp)
        .about("Manage a beacon node database")
        .arg(
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
            Arg::with_name("freezer-dir")
                .long("freezer-dir")
                .value_name("DIR")
                .help("Data directory for the freezer database.")
                .takes_value(true),
        )
        .subcommand(migrate_cli_app())
        .subcommand(version_cli_app())
        .subcommand(inspect_cli_app())
        .subcommand(prune_payloads_app())
        .subcommand(diff_app())
}

fn parse_client_config<E: EthSpec>(
    cli_args: &ArgMatches,
    _env: &Environment<E>,
) -> Result<ClientConfig, String> {
    let mut client_config = ClientConfig::default();

    client_config.set_data_dir(get_data_dir(cli_args));

    if let Some(freezer_dir) = clap_utils::parse_optional(cli_args, "freezer-dir")? {
        client_config.freezer_db_path = Some(freezer_dir);
    }

    Ok(client_config)
}

pub fn display_db_version<E: EthSpec>(
    client_config: ClientConfig,
    runtime_context: &RuntimeContext<E>,
    log: Logger,
) -> Result<(), Error> {
    let spec = runtime_context.eth2_config.spec.clone();
    let hot_path = client_config.get_db_path();
    let cold_path = client_config.get_freezer_db_path();

    let mut version = CURRENT_SCHEMA_VERSION;
    HotColdDB::<E, LevelDB<E>, LevelDB<E>>::open(
        &hot_path,
        &cold_path,
        |_, from, _| {
            version = from;
            Ok(())
        },
        client_config.store,
        spec,
        log.clone(),
    )?;

    info!(log, "Database version: {}", version.as_u64());

    if version != CURRENT_SCHEMA_VERSION {
        info!(
            log,
            "Latest schema version: {}",
            CURRENT_SCHEMA_VERSION.as_u64(),
        );
    }

    Ok(())
}

#[derive(Debug, PartialEq, Eq, EnumString, EnumVariantNames)]
pub enum InspectTarget {
    #[strum(serialize = "sizes")]
    ValueSizes,
    #[strum(serialize = "total")]
    ValueTotal,
    #[strum(serialize = "values")]
    Values,
    #[strum(serialize = "gaps")]
    Gaps,
}

pub struct InspectConfig {
    column: DBColumn,
    target: InspectTarget,
    skip: Option<usize>,
    limit: Option<usize>,
    freezer: bool,
    /// Configures where the inspect output should be stored.
    output_dir: PathBuf,
}

fn parse_inspect_config(cli_args: &ArgMatches) -> Result<InspectConfig, String> {
    let column = clap_utils::parse_required(cli_args, "column")?;
    let target = clap_utils::parse_required(cli_args, "output")?;
    let skip = clap_utils::parse_optional(cli_args, "skip")?;
    let limit = clap_utils::parse_optional(cli_args, "limit")?;
    let freezer = cli_args.is_present("freezer");

    let output_dir: PathBuf =
        clap_utils::parse_optional(cli_args, "output-dir")?.unwrap_or_else(PathBuf::new);
    Ok(InspectConfig {
        column,
        target,
        skip,
        limit,
        freezer,
        output_dir,
    })
}

pub fn inspect_db<E: EthSpec>(
    inspect_config: InspectConfig,
    client_config: ClientConfig,
    runtime_context: &RuntimeContext<E>,
    log: Logger,
) -> Result<(), String> {
    let spec = runtime_context.eth2_config.spec.clone();
    let hot_path = client_config.get_db_path();
    let cold_path = client_config.get_freezer_db_path();

    let db = HotColdDB::<E, LevelDB<E>, LevelDB<E>>::open(
        &hot_path,
        &cold_path,
        |_, _, _| Ok(()),
        client_config.store,
        spec,
        log,
    )
    .map_err(|e| format!("{:?}", e))?;

    let mut total = 0;
    let mut num_keys = 0;

    let sub_db = if inspect_config.freezer {
        &db.cold_db
    } else {
        &db.hot_db
    };

    let skip = inspect_config.skip.unwrap_or(0);
    let limit = inspect_config.limit.unwrap_or(usize::MAX);

    let mut prev_key = 0;
    let mut found_gaps = false;

    let base_path = &inspect_config.output_dir;

    if let InspectTarget::Values = inspect_config.target {
        fs::create_dir_all(base_path)
            .map_err(|e| format!("Unable to create import directory: {:?}", e))?;
    }

    for res in sub_db
        .iter_column::<Vec<u8>>(inspect_config.column)
        .skip(skip)
        .take(limit)
    {
        let (key, value) = res.map_err(|e| format!("{:?}", e))?;

        match inspect_config.target {
            InspectTarget::ValueSizes => {
                println!("{}: {} bytes", hex::encode(&key), value.len());
            }
            InspectTarget::Gaps => {
                // Convert last 8 bytes of key to u64.
                let numeric_key = u64::from_be_bytes(
                    key[key.len() - 8..]
                        .try_into()
                        .expect("key is at least 8 bytes"),
                );

                if numeric_key > prev_key + 1 {
                    println!(
                        "gap between keys {} and {} (offset: {})",
                        prev_key, numeric_key, num_keys,
                    );
                    found_gaps = true;
                }
                prev_key = numeric_key;
            }
            InspectTarget::ValueTotal => (),
            InspectTarget::Values => {
                let file_path = base_path.join(format!(
                    "{}_{}.ssz",
                    inspect_config.column.as_str(),
                    hex::encode(&key)
                ));

                let write_result = fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .open(&file_path)
                    .map_err(|e| format!("Failed to open file: {:?}", e))
                    .map(|mut file| {
                        file.write_all(&value)
                            .map_err(|e| format!("Failed to write file: {:?}", e))
                    });
                if let Err(e) = write_result {
                    println!("Error writing values to file {:?}: {:?}", file_path, e);
                } else {
                    println!("Successfully saved values to file: {:?}", file_path);
                }

                total += value.len();
            }
        }
        total += value.len();
        num_keys += 1;
    }

    if inspect_config.target == InspectTarget::Gaps && !found_gaps {
        println!("No gaps found!");
    }

    println!("Num keys: {}", num_keys);
    println!("Total: {} bytes", total);

    Ok(())
}

pub struct MigrateConfig {
    to: SchemaVersion,
}

fn parse_migrate_config(cli_args: &ArgMatches) -> Result<MigrateConfig, String> {
    let to = SchemaVersion(clap_utils::parse_required(cli_args, "to")?);

    Ok(MigrateConfig { to })
}

pub fn migrate_db<E: EthSpec>(
    migrate_config: MigrateConfig,
    client_config: ClientConfig,
    runtime_context: &RuntimeContext<E>,
    log: Logger,
) -> Result<(), Error> {
    let spec = &runtime_context.eth2_config.spec;
    let hot_path = client_config.get_db_path();
    let cold_path = client_config.get_freezer_db_path();

    let mut from = CURRENT_SCHEMA_VERSION;
    let to = migrate_config.to;
    let db = HotColdDB::<E, LevelDB<E>, LevelDB<E>>::open(
        &hot_path,
        &cold_path,
        |_, db_initial_version, _| {
            from = db_initial_version;
            Ok(())
        },
        client_config.store.clone(),
        spec.clone(),
        log.clone(),
    )?;

    info!(
        log,
        "Migrating database schema";
        "from" => from.as_u64(),
        "to" => to.as_u64(),
    );

    migrate_schema::<Witness<SystemTimeSlotClock, CachingEth1Backend<E>, _, _, _>>(
        db,
        client_config.eth1.deposit_contract_deploy_block,
        from,
        to,
        log,
        spec,
    )
}

pub struct DiffConfig {
    first: PathBuf,
    second: PathBuf,
}

fn parse_diff_config(cli_args: &ArgMatches) -> Result<DiffConfig, String> {
    let first = clap_utils::parse_required(cli_args, "first")?;
    let second = clap_utils::parse_required(cli_args, "second")?;

    Ok(DiffConfig { first, second })
}

pub fn diff<E: EthSpec>(diff_config: &DiffConfig, log: Logger) -> Result<(), Error> {
    use ssz::{Decode, Encode};
    use std::fs::File;
    use std::io::Read;
    use store::StoreConfig;

    let mut first_file = File::open(&diff_config.first).unwrap();
    let mut second_file = File::open(&diff_config.second).unwrap();

    let mut first_bytes = vec![];
    first_file.read_to_end(&mut first_bytes).unwrap();
    let first: VList<u64, E::ValidatorRegistryLimit> = VList::from_ssz_bytes(&first_bytes).unwrap();

    let mut second_bytes = vec![];
    second_file.read_to_end(&mut second_bytes).unwrap();
    let second: VList<u64, E::ValidatorRegistryLimit> =
        VList::from_ssz_bytes(&second_bytes).unwrap();

    let mut diff_balances = Vec::with_capacity(second.len());

    for (i, new_balance) in second.iter().enumerate() {
        let old_balance = first.get(i).copied().unwrap_or(0);
        let diff = new_balance.wrapping_sub(old_balance);
        diff_balances.push(diff);
    }

    let diff_ssz_bytes = diff_balances.as_ssz_bytes();
    let config = StoreConfig::default();
    let compressed_diff_bytes = config.compress_bytes(&diff_ssz_bytes).unwrap();

    info!(
        log,
        "Compressed diff to {} bytes (from {})",
        compressed_diff_bytes.len(),
        diff_ssz_bytes.len()
    );
    Ok(())
}

pub fn prune_payloads<E: EthSpec>(
    client_config: ClientConfig,
    runtime_context: &RuntimeContext<E>,
    log: Logger,
) -> Result<(), Error> {
    let spec = &runtime_context.eth2_config.spec;
    let hot_path = client_config.get_db_path();
    let cold_path = client_config.get_freezer_db_path();

    let db = HotColdDB::<E, LevelDB<E>, LevelDB<E>>::open(
        &hot_path,
        &cold_path,
        |_, _, _| Ok(()),
        client_config.store,
        spec.clone(),
        log,
    )?;

    // If we're trigging a prune manually then ignore the check on the split's parent that bails
    // out early.
    let force = true;
    db.try_prune_execution_payloads(force)
}

/// Run the database manager, returning an error string if the operation did not succeed.
pub fn run<T: EthSpec>(cli_args: &ArgMatches<'_>, env: Environment<T>) -> Result<(), String> {
    let client_config = parse_client_config(cli_args, &env)?;
    let context = env.core_context();
    let log = context.log().clone();
    let format_err = |e| format!("Fatal error: {:?}", e);

    match cli_args.subcommand() {
        ("version", Some(_)) => {
            display_db_version(client_config, &context, log).map_err(format_err)
        }
        ("migrate", Some(cli_args)) => {
            let migrate_config = parse_migrate_config(cli_args)?;
            migrate_db(migrate_config, client_config, &context, log).map_err(format_err)
        }
        ("inspect", Some(cli_args)) => {
            let inspect_config = parse_inspect_config(cli_args)?;
            inspect_db(inspect_config, client_config, &context, log)
        }
        ("prune_payloads", Some(_)) => {
            prune_payloads(client_config, &context, log).map_err(format_err)
        }
        ("diff", Some(cli_args)) => {
            let diff_config = parse_diff_config(cli_args)?;
            diff::<T>(&diff_config, log).map_err(format_err)
        }
        _ => Err("Unknown subcommand, for help `lighthouse database_manager --help`".into()),
    }
}
