use crate::VALIDATOR_DIR_FLAG;
use clap::{App, Arg, ArgMatches};
use directory::{custom_base_dir, DEFAULT_VALIDATOR_DIR};
use validator_dir::Manager as ValidatorManager;

pub const CMD: &str = "list";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .arg(
            Arg::with_name(VALIDATOR_DIR_FLAG)
                .long(VALIDATOR_DIR_FLAG)
                .value_name("VALIDATOR_DIRECTORY")
                .help(
                    "The path to search for validator directories. \
                    Defaults to ~/.lighthouse/{testnet}/validators",
                )
                .takes_value(true),
        )
        .about("Lists the names of all validators.")
}

pub fn cli_run(matches: &ArgMatches<'_>) -> Result<(), String> {
    let data_dir = custom_base_dir(matches, VALIDATOR_DIR_FLAG, DEFAULT_VALIDATOR_DIR)?;

    let mgr = ValidatorManager::open(&data_dir)
        .map_err(|e| format!("Unable to read --{}: {:?}", VALIDATOR_DIR_FLAG, e))?;

    for (name, _path) in mgr
        .directory_names()
        .map_err(|e| format!("Unable to list wallets: {:?}", e))?
    {
        println!("{}", name)
    }

    Ok(())
}
