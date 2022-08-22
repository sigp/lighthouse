use clap::App;
use clap::ArgMatches;
use environment::Environment;
use serde::Serialize;
use std::path::PathBuf;
use types::EthSpec;
use validators::create_validators::write_to_json_file;

mod validators;

pub const CMD: &str = "validator_manager";

/// This flag is on the top-level `lighthouse` binary.
const DUMP_CONFIGS_FLAG: &str = "dump-configs";

/// Used only in testing, this allows a command to dump its configuration to a file and then exit
/// successfully. This allows for testing how the CLI arguments translate to some configuration.
pub enum DumpConfigs {
    Disabled,
    Enabled(PathBuf),
}

impl DumpConfigs {
    /// Returns `Ok(true)` if the configuration was successfully written to a file and the
    /// application should exit successfully without doing anything else.
    pub fn should_exit_early<T: Serialize>(&self, config: &T) -> Result<bool, String> {
        match self {
            DumpConfigs::Disabled => Ok(false),
            DumpConfigs::Enabled(dump_path) => write_to_json_file(dump_path, config).map(|()| true),
        }
    }
}

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .visible_aliases(&["vm", CMD])
        .about("Utilities for managing a Lighthouse validator client via the HTTP API.")
        .subcommand(validators::cli_app())
}

/// Run the account manager, returning an error if the operation did not succeed.
pub fn run<'a, T: EthSpec>(
    matches: &'a ArgMatches<'a>,
    mut env: Environment<T>,
) -> Result<(), String> {
    let context = env.core_context();
    let spec = context.eth2_config.spec.clone();
    let dump_configs = clap_utils::parse_optional(matches, DUMP_CONFIGS_FLAG)?
        .map(DumpConfigs::Enabled)
        .unwrap_or_else(|| DumpConfigs::Disabled);

    context
        .executor
        // This `block_on_dangerous` call reasonable since it is at the very highest level of the
        // application, the rest of which is all async. All other functions below this should be
        // async and should never call `block_on_dangerous` themselves.
        .block_on_dangerous(
            async {
                match matches.subcommand() {
                    (validators::CMD, Some(matches)) => {
                        validators::cli_run::<T>(matches, &spec, dump_configs).await
                    }
                    (unknown, _) => Err(format!(
                        "{} is not a valid {} command. See --help.",
                        unknown, CMD
                    )),
                }
            },
            "validator_manager",
        )
        .ok_or("Shutting down")?
}
