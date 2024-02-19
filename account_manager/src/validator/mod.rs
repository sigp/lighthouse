pub mod cli;
pub mod create;
pub mod exit;
pub mod import;
pub mod list;
pub mod modify;
pub mod recover;
pub mod slashing_protection;

use clap_utils::GlobalConfig;
use directory::{parse_path_or_default_with_flag, DEFAULT_VALIDATOR_DIR};
use environment::Environment;
use types::EthSpec;

use self::cli::Validator;

pub const CMD: &str = "validator";

pub fn cli_run<T: EthSpec>(
    validator_config: &Validator,
    global_config: &GlobalConfig,
    env: Environment<T>,
) -> Result<(), String> {
    let validator_base_dir = if let Some(datadir) = global_config.datadir.as_ref() {
        datadir.join(DEFAULT_VALIDATOR_DIR)
    } else {
        parse_path_or_default_with_flag(
            global_config,
            validator_config.validator_dir.clone(),
            DEFAULT_VALIDATOR_DIR,
        )?
    };
    eprintln!("validator-dir path: {:?}", validator_base_dir);

    match &validator_config.subcommand {
        cli::ValidatorSubcommand::Create(create_config) => {
            create::cli_run::<T>(create_config, global_config, env, validator_base_dir)
        }
        cli::ValidatorSubcommand::Exit(exit_config) => exit::cli_run(exit_config, env),
        cli::ValidatorSubcommand::Import(import_config) => {
            import::cli_run(import_config, validator_base_dir)
        }
        cli::ValidatorSubcommand::List(_) => list::cli_run(validator_base_dir),
        cli::ValidatorSubcommand::Recover(recover_config) => {
            recover::cli_run(recover_config, global_config, validator_base_dir)
        }
        cli::ValidatorSubcommand::Modify(modify_config) => {
            modify::cli_run(modify_config, validator_base_dir)
        }
        cli::ValidatorSubcommand::SlashingProtection(slashing_protection_config) => {
            slashing_protection::cli_run(slashing_protection_config, env, validator_base_dir)
        }
    }
}
