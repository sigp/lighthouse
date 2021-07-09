use clap::{App, Arg, ArgMatches};
use environment::Environment;
use slashing_protection::{
    interchange::Interchange, InterchangeError, InterchangeImportOutcome, SlashingDatabase,
    SLASHING_PROTECTION_FILENAME,
};
use std::fs::File;
use std::path::PathBuf;
use types::{BeaconState, Epoch, EthSpec, Slot};

pub const CMD: &str = "slashing-protection";
pub const IMPORT_CMD: &str = "import";
pub const EXPORT_CMD: &str = "export";

pub const IMPORT_FILE_ARG: &str = "IMPORT-FILE";
pub const EXPORT_FILE_ARG: &str = "EXPORT-FILE";

pub const MINIFY_FLAG: &str = "minify";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about("Import or export slashing protection data to or from another client")
        .subcommand(
            App::new(IMPORT_CMD)
                .about("Import an interchange file")
                .arg(
                    Arg::with_name(IMPORT_FILE_ARG)
                        .takes_value(true)
                        .value_name("FILE")
                        .help("The slashing protection interchange file to import (.json)"),
                )
                .arg(
                    Arg::with_name(MINIFY_FLAG)
                        .long(MINIFY_FLAG)
                        .takes_value(true)
                        .default_value("true")
                        .possible_values(&["false", "true"])
                        .help(
                            "Minify the input file before processing. This is *much* faster, \
                             but will not detect slashable data in the input.",
                        ),
                ),
        )
        .subcommand(
            App::new(EXPORT_CMD)
                .about("Export an interchange file")
                .arg(
                    Arg::with_name(EXPORT_FILE_ARG)
                        .takes_value(true)
                        .value_name("FILE")
                        .help("The filename to export the interchange file to"),
                )
                .arg(
                    Arg::with_name(MINIFY_FLAG)
                        .long(MINIFY_FLAG)
                        .takes_value(true)
                        .default_value("false")
                        .possible_values(&["false", "true"])
                        .help(
                            "Minify the output file. This will make it smaller and faster to \
                             import, but not faster to generate.",
                        ),
                ),
        )
}

pub fn cli_run<T: EthSpec>(
    matches: &ArgMatches<'_>,
    env: Environment<T>,
    validator_base_dir: PathBuf,
) -> Result<(), String> {
    let slashing_protection_db_path = validator_base_dir.join(SLASHING_PROTECTION_FILENAME);

    let testnet_config = env
        .testnet
        .ok_or("Unable to get testnet configuration from the environment")?;

    let genesis_validators_root = testnet_config
        .beacon_state::<T>()
        .map(|state: BeaconState<T>| state.genesis_validators_root())
        .map_err(|e| {
            format!(
                "Unable to get genesis state, has genesis occurred? Detail: {:?}",
                e
            )
        })?;

    match matches.subcommand() {
        (IMPORT_CMD, Some(matches)) => {
            let import_filename: PathBuf = clap_utils::parse_required(&matches, IMPORT_FILE_ARG)?;
            let minify: bool = clap_utils::parse_required(&matches, MINIFY_FLAG)?;
            let import_file = File::open(&import_filename).map_err(|e| {
                format!(
                    "Unable to open import file at {}: {:?}",
                    import_filename.display(),
                    e
                )
            })?;

            eprint!("Loading JSON file into memory & deserializing");
            let mut interchange = Interchange::from_json_reader(&import_file)
                .map_err(|e| format!("Error parsing file for import: {:?}", e))?;
            eprintln!(" [done].");

            if minify {
                eprint!("Minifying input file for faster loading");
                interchange = interchange
                    .minify()
                    .map_err(|e| format!("Minification failed: {:?}", e))?;
                eprintln!(" [done].");
            }

            let slashing_protection_database =
                SlashingDatabase::open_or_create(&slashing_protection_db_path).map_err(|e| {
                    format!(
                        "Unable to open database at {}: {:?}",
                        slashing_protection_db_path.display(),
                        e
                    )
                })?;

            let display_slot = |slot: Option<Slot>| {
                slot.map_or("none".to_string(), |slot| format!("{}", slot.as_u64()))
            };
            let display_epoch = |epoch: Option<Epoch>| {
                epoch.map_or("?".to_string(), |epoch| format!("{}", epoch.as_u64()))
            };
            let display_attestation = |source, target| match (source, target) {
                (None, None) => "none".to_string(),
                (source, target) => format!("{}=>{}", display_epoch(source), display_epoch(target)),
            };

            match slashing_protection_database
                .import_interchange_info(interchange, genesis_validators_root)
            {
                Ok(outcomes) => {
                    eprintln!("All records imported successfully:");
                    for outcome in &outcomes {
                        match outcome {
                            InterchangeImportOutcome::Success { pubkey, summary } => {
                                eprintln!("- {:?}", pubkey);
                                eprintln!(
                                    "    - min block: {}",
                                    display_slot(summary.min_block_slot)
                                );
                                eprintln!(
                                    "    - min attestation: {}",
                                    display_attestation(
                                        summary.min_attestation_source,
                                        summary.min_attestation_target
                                    )
                                );
                                eprintln!(
                                    "    - max attestation: {}",
                                    display_attestation(
                                        summary.max_attestation_source,
                                        summary.max_attestation_target
                                    )
                                );
                            }
                            InterchangeImportOutcome::Failure { pubkey, error } => {
                                panic!(
                                    "import should be atomic, but key {:?} was imported despite error: {:?}",
                                    pubkey, error
                                );
                            }
                        }
                    }
                }
                Err(InterchangeError::AtomicBatchAborted(outcomes)) => {
                    eprintln!("ERROR, slashable data in input:");
                    for outcome in &outcomes {
                        if let InterchangeImportOutcome::Failure { pubkey, error } = outcome {
                            eprintln!("- {:?}", pubkey);
                            eprintln!("    - error: {:?}", error);
                        }
                    }
                    return Err(
                        "ERROR: import aborted due to slashable data, see above.\n\
                         Please see https://lighthouse-book.sigmaprime.io/slashing-protection.html#slashable-data-in-import\n\
                         IT IS NOT SAFE TO START VALIDATING".to_string()
                    );
                }
                Err(e) => {
                    return Err(format!(
                        "Fatal error during import: {:?}\n\
                         IT IS NOT SAFE TO START VALIDATING",
                        e
                    ));
                }
            }

            eprintln!("Import completed successfully.");
            eprintln!(
                "Please double-check that the minimum and maximum blocks and attestations above \
                 match your expectations."
            );

            Ok(())
        }
        (EXPORT_CMD, Some(matches)) => {
            let export_filename: PathBuf = clap_utils::parse_required(&matches, EXPORT_FILE_ARG)?;
            let minify: bool = clap_utils::parse_required(&matches, MINIFY_FLAG)?;

            if !slashing_protection_db_path.exists() {
                return Err(format!(
                    "No slashing protection database exists at: {}",
                    slashing_protection_db_path.display()
                ));
            }

            let slashing_protection_database = SlashingDatabase::open(&slashing_protection_db_path)
                .map_err(|e| {
                    format!(
                        "Unable to open database at {}: {:?}",
                        slashing_protection_db_path.display(),
                        e
                    )
                })?;

            let mut interchange = slashing_protection_database
                .export_interchange_info(genesis_validators_root)
                .map_err(|e| format!("Error during export: {:?}", e))?;

            if minify {
                eprintln!("Minifying output file");
                interchange = interchange
                    .minify()
                    .map_err(|e| format!("Unable to minify output: {:?}", e))?;
            }

            let output_file = File::create(export_filename)
                .map_err(|e| format!("Error creating output file: {:?}", e))?;

            interchange
                .write_to(&output_file)
                .map_err(|e| format!("Error writing output file: {:?}", e))?;

            eprintln!("Export completed successfully");

            Ok(())
        }
        ("", _) => Err("No subcommand provided, see --help for options".to_string()),
        (command, _) => Err(format!("No such subcommand `{}`", command)),
    }
}
