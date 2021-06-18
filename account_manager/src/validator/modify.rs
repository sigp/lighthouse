use account_utils::validator_definitions::ValidatorDefinitions;
use bls::PublicKey;
use clap::{App, Arg, ArgMatches};
use std::{collections::HashSet, path::PathBuf};

pub const CMD: &str = "modify";
pub const ENABLE: &str = "enable";
pub const DISABLE: &str = "disable";

pub const PUBKEY_FLAG: &str = "pubkey";
pub const ALL: &str = "all";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about("Modify validator status in validator_definitions.yml.")
        .subcommand(
            App::new(ENABLE)
                .about("Enable validator(s) in validator_definitions.yml.")
                .arg(
                    Arg::with_name(PUBKEY_FLAG)
                        .long(PUBKEY_FLAG)
                        .value_name("PUBKEY")
                        .help("Validator pubkey to enable")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name(ALL)
                        .long(ALL)
                        .help("Enable all validators in the validator directory")
                        .takes_value(false)
                        .conflicts_with(PUBKEY_FLAG),
                ),
        )
        .subcommand(
            App::new(DISABLE)
                .about("Disable validator(s) in validator_definitions.yml.")
                .arg(
                    Arg::with_name(PUBKEY_FLAG)
                        .long(PUBKEY_FLAG)
                        .value_name("PUBKEY")
                        .help("Validator pubkey to disable")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name(ALL)
                        .long(ALL)
                        .help("Disable all validators in the validator directory")
                        .takes_value(false)
                        .conflicts_with(PUBKEY_FLAG),
                ),
        )
}

pub fn cli_run(matches: &ArgMatches, validator_dir: PathBuf) -> Result<(), String> {
    // `true` implies we are setting `validator_definition.enabled = true` and
    // vice versa.
    let (enabled, sub_matches) = match matches.subcommand() {
        (ENABLE, Some(sub_matches)) => (true, sub_matches),
        (DISABLE, Some(sub_matches)) => (false, sub_matches),
        (unknown, _) => {
            return Err(format!(
                "{} does not have a {} command. See --help",
                CMD, unknown
            ))
        }
    };
    let mut defs = ValidatorDefinitions::open(&validator_dir).map_err(|e| {
        format!(
            "No validator definitions found in {:?}: {:?}",
            validator_dir, e
        )
    })?;
    let pubkeys_to_modify = if sub_matches.is_present(ALL) {
        defs.as_slice()
            .iter()
            .map(|def| def.voting_public_key.clone())
            .collect::<HashSet<_>>()
    } else {
        let public_key: PublicKey = clap_utils::parse_required(sub_matches, PUBKEY_FLAG)?;
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
