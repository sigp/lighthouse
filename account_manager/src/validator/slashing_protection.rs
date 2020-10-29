use clap::{App, Arg, ArgMatches};
use environment::Environment;
use slashing_protection::{
    interchange::Interchange, SlashingDatabase, SLASHING_PROTECTION_FILENAME,
};
use std::fs::File;
use std::path::PathBuf;
use types::{BeaconState, EthSpec};

pub const CMD: &str = "slashing-protection";
pub const IMPORT_CMD: &str = "import";
pub const EXPORT_CMD: &str = "export";

pub const IMPORT_FILE_ARG: &str = "IMPORT-FILE";
pub const EXPORT_FILE_ARG: &str = "EXPORT-FILE";

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
                ),
        )
}

pub fn cli_run<T: EthSpec>(
    matches: &ArgMatches<'_>,
    env: Environment<T>,
    validator_base_dir: PathBuf,
) -> Result<(), String> {
    eprintln!("validator-dir path: {:?}", validator_base_dir);
    let slashing_protection_db_path = validator_base_dir.join(SLASHING_PROTECTION_FILENAME);

    let testnet_config = env
        .testnet
        .ok_or_else(|| "Unable to get testnet configuration from the environment".to_string())?;

    let genesis_validators_root = testnet_config
        .beacon_state::<T>()
        .map(|state: BeaconState<T>| state.genesis_validators_root)
        .map_err(|e| {
            format!(
                "Unable to get genesis state, has genesis occurred? Detail: {:?}",
                e
            )
        })?;

    match matches.subcommand() {
        (IMPORT_CMD, Some(matches)) => {
            let import_filename: PathBuf = clap_utils::parse_required(&matches, IMPORT_FILE_ARG)?;
            let import_file = File::open(&import_filename).map_err(|e| {
                format!(
                    "Unable to open import file at {}: {:?}",
                    import_filename.display(),
                    e
                )
            })?;

            let interchange = Interchange::from_json_reader(&import_file)
                .map_err(|e| format!("Error parsing file for import: {:?}", e))?;

            let slashing_protection_database =
                SlashingDatabase::open_or_create(&slashing_protection_db_path).map_err(|e| {
                    format!(
                        "Unable to open database at {}: {:?}",
                        slashing_protection_db_path.display(),
                        e
                    )
                })?;

            slashing_protection_database
                .import_interchange_info(&interchange, genesis_validators_root)
                .map_err(|e| {
                    format!(
                        "Error during import, no data imported: {:?}\n\
                         IT IS NOT SAFE TO START VALIDATING",
                        e
                    )
                })?;

            eprintln!("Import completed successfully");

            Ok(())
        }
        (EXPORT_CMD, Some(matches)) => {
            let export_filename: PathBuf = clap_utils::parse_required(&matches, EXPORT_FILE_ARG)?;

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

            let interchange = slashing_protection_database
                .export_interchange_info(genesis_validators_root)
                .map_err(|e| format!("Error during export: {:?}", e))?;

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
