use account_utils::validator_definitions::ValidatorDefinitions;
use clap::App;
use std::path::PathBuf;

pub const CMD: &str = "list";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD).about("Lists the public keys of all validators.")
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
