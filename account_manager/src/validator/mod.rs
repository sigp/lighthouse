pub mod cli;
pub mod create;
pub mod exit;
pub mod import;
pub mod list;
pub mod modify;
pub mod recover;
pub mod slashing_protection;

use clap::ArgMatches;
use cli::Validator;
use directory::{parse_path_or_default_with_flag_v2, DEFAULT_VALIDATOR_DIR};
use environment::Environment;
use std::path::PathBuf;
use types::EthSpec;

pub fn cli_run<E: EthSpec>(
    validator_config: &Validator,
    matches: &ArgMatches,
    env: Environment<E>,
) -> Result<(), String> {
    let validator_base_dir = if matches.get_one::<String>("datadir").is_some() {
        let path: PathBuf = clap_utils::parse_required(matches, "datadir")?;
        path.join(DEFAULT_VALIDATOR_DIR)
    } else {
        parse_path_or_default_with_flag_v2(
            matches,
            validator_config.validator_dir.clone(),
            DEFAULT_VALIDATOR_DIR,
        )?
    };
    eprintln!("validator-dir path: {:?}", validator_base_dir);

    match &validator_config.subcommand {
        cli::ValidatorSubcommand::Create(create_config) => {
            create::cli_run::<E>(create_config, matches, env, validator_base_dir)
        }
        cli::ValidatorSubcommand::Exit(exit_config) => exit::cli_run(exit_config, matches, env),
        cli::ValidatorSubcommand::Import(import_config) => {
            import::cli_run(import_config, matches, validator_base_dir)
        }
        cli::ValidatorSubcommand::List(_) => list::cli_run(validator_base_dir),
        cli::ValidatorSubcommand::Recover(recover_config) => {
            recover::cli_run(recover_config, matches, validator_base_dir)
        }
        cli::ValidatorSubcommand::Modify(modify_config) => {
            modify::cli_run(modify_config, validator_base_dir)
        }
        cli::ValidatorSubcommand::SlashingProtection(slashing_protection_config) => {
            slashing_protection::cli_run(slashing_protection_config, env, validator_base_dir)
        }
    }
}
