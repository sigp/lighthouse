use account_utils::validator_definitions::ValidatorDefinitions;
use bls::PublicKey;
use std::{collections::HashSet, path::PathBuf};

use crate::validator::cli::Modifiable;

use super::cli::Modify;

pub fn cli_run(modify_config: &Modify, validator_dir: PathBuf) -> Result<(), String> {
    // `true` implies we are setting `validator_definition.enabled = true` and
    // vice versa.
    let (enabled, sub_matches) = match modify_config {
        Modify::Enable(sub_matches) => (true, Box::new(sub_matches) as Box<dyn Modifiable>),
        Modify::Disable(sub_matches) => (false, Box::new(sub_matches) as Box<dyn Modifiable>),
    };

    let mut defs = ValidatorDefinitions::open(&validator_dir).map_err(|e| {
        format!(
            "No validator definitions found in {:?}: {:?}",
            validator_dir, e
        )
    })?;

    let pubkeys_to_modify = if sub_matches.is_all() {
        defs.as_slice()
            .iter()
            .map(|def| def.voting_public_key.clone())
            .collect::<HashSet<_>>()
    } else {
        let public_key = sub_matches
            .get_pubkey()
            .ok_or_else(|| "Pubkey flag must be provided.".to_string())?;
        std::iter::once(public_key).collect::<HashSet<PublicKey>>()
    };

    // Modify required entries from  validator_definitions.
    for def in defs.as_mut_slice() {
        if pubkeys_to_modify.contains(&def.voting_public_key) {
            def.enabled = enabled;
            eprintln!(
                "Validator {} {}",
                def.voting_public_key,
                if enabled { "enabled" } else { "disabled" }
            );
        }
    }

    defs.save(&validator_dir)
        .map_err(|e| format!("Unable to modify validator definitions: {:?}", e))?;

    eprintln!("\nSuccessfully modified validator_definitions.yml");
    Ok(())
}
