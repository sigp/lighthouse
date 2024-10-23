use account_utils::validator_definitions::ValidatorDefinitions;
use std::path::PathBuf;

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
