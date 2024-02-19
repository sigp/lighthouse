use clap_utils::GlobalConfig;
use cli::ValidatorManager;
use common::write_to_json_file;
use environment::Environment;
use serde::Serialize;
use std::path::PathBuf;
use types::EthSpec;

pub mod cli;
pub mod common;
pub mod create_validators;
pub mod import_validators;
pub mod move_validators;

pub const CMD: &str = "validator_manager";

/// Used only in testing, this allows a command to dump its configuration to a file and then exit
/// successfully. This allows for testing how the CLI arguments translate to some configuration.
pub enum DumpConfig {
    Disabled,
    Enabled(PathBuf),
}

impl DumpConfig {
    /// Returns `Ok(true)` if the configuration was successfully written to a file and the
    /// application should exit successfully without doing anything else.
    pub fn should_exit_early<T: Serialize>(&self, config: &T) -> Result<bool, String> {
        match self {
            DumpConfig::Disabled => Ok(false),
            DumpConfig::Enabled(dump_path) => {
                dbg!(dump_path);
                write_to_json_file(dump_path, config)?;
                Ok(true)
            }
        }
    }
}

/// Run the account manager, returning an error if the operation did not succeed.
pub fn run<T: EthSpec>(
    validator_mananager_config: &ValidatorManager,
    global_config: &GlobalConfig,
    env: Environment<T>,
) -> Result<(), String> {
    let context = env.core_context();
    let spec = context.eth2_config.spec;
    let dump_config = global_config
        .dump_config
        .clone()
        .map(DumpConfig::Enabled)
        .unwrap_or_else(|| DumpConfig::Disabled);

    context
        .executor
        // This `block_on_dangerous` call reasonable since it is at the very highest level of the
        // application, the rest of which is all async. All other functions below this should be
        // async and should never call `block_on_dangerous` themselves.
        .block_on_dangerous(
            async {
                match &validator_mananager_config.subcommand {
                    cli::ValidatorManagerSubcommand::Create(create_config) => {
                        create_validators::cli_run::<T>(create_config, &spec, dump_config).await
                    }
                    cli::ValidatorManagerSubcommand::Import(import_config) => {
                        import_validators::cli_run(import_config, dump_config).await
                    }
                    cli::ValidatorManagerSubcommand::Move(move_config) => {
                        move_validators::cli_run(move_config, dump_config).await
                    }
                }
            },
            "validator_manager",
        )
        .ok_or("Shutting down")?
}
