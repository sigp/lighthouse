use account_utils::validator_definitions::ValidatorDefinitions;
use clap::{Arg, ArgAction, Command};
use clap_utils::FLAG_HEADER;
use std::path::PathBuf;

pub const CMD: &str = "list";

pub fn cli_app() -> Command {
    Command::new(CMD)
        .about("Lists the public keys of all validators.")
        .arg(
            Arg::new("help")
                .long("help")
                .short('h')
                .help("Prints help information")
                .action(ArgAction::HelpLong)
                .display_order(0)
                .help_heading(FLAG_HEADER),
        )
}

pub fn cli_run(validator_dir: PathBuf) -> Result<(), String> {
    let validator_definitions = ValidatorDefinitions::open(&validator_dir).map_err(|e| {
        format!(
            "No validator definitions found in {:?}: {:?}",
            validator_dir, e
        )
    })?;

    for def in validator_definitions.as_slice() {
        println!(
            "{} ({})",
            def.voting_public_key,
            if def.enabled { "enabled" } else { "disabled" }
        );
    }

    Ok(())
}
