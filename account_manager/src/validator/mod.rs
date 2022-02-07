pub mod cli;
pub mod create;
pub mod exit;
pub mod import;
pub mod list;
pub mod modify;
pub mod recover;
pub mod slashing_protection;

use crate::validator::cli::{Validator, ValidatorSubcommand};
use clap_utils::GlobalConfig;
use directory::{parse_path_or_default_with_flag, DEFAULT_VALIDATOR_DIR};
use environment::Environment;
use types::EthSpec;

pub const CMD: &str = "validator";

pub fn cli_run<T: EthSpec>(
    valdiator_config: &Validator,
    global_config: &GlobalConfig,
    env: Environment<T>,
) -> Result<(), String> {
    let validator_base_dir = if let Some(datadir) = global_config.datadir.as_ref() {
        datadir.join(DEFAULT_VALIDATOR_DIR)
    } else {
        parse_path_or_default_with_flag(
            valdiator_config.validator_dir.clone(),
            global_config,
            DEFAULT_VALIDATOR_DIR,
        )?
    };
    eprintln!("validator-dir path: {:?}", validator_base_dir);

    match &valdiator_config.subcommand {
        ValidatorSubcommand::Create(create_config) => {
            create::cli_run::<T>(&create_config, global_config, env, validator_base_dir)
        }
        ValidatorSubcommand::Modify(modify_config) => {
            modify::cli_run(&modify_config, validator_base_dir)
        }
        ValidatorSubcommand::Import(import_config) => {
            import::cli_run(&import_config, validator_base_dir)
        }
        ValidatorSubcommand::List(_) => list::cli_run(validator_base_dir),
        ValidatorSubcommand::Recover(recover_config) => {
            recover::cli_run(&recover_config, global_config, validator_base_dir)
        }
        ValidatorSubcommand::SlashingProtection(slashingprotection_config) => {
            slashing_protection::cli_run(&slashingprotection_config, env, validator_base_dir)
        }
        ValidatorSubcommand::Exit(exit_config) => exit::cli_run(&exit_config, env),
    }
}
