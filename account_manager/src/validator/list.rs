use crate::VALIDATOR_DIR_FLAG;
use clap::{App, ArgMatches};
use std::path::PathBuf;
use validator_dir::Manager as ValidatorManager;

pub const CMD: &str = "list";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD).about("Lists the names of all validators.")
}

pub fn cli_run(matches: &ArgMatches<'_>) -> Result<(), String> {
    let data_dir = clap_utils::parse_path_with_default_in_home_dir(
        matches,
        VALIDATOR_DIR_FLAG,
        PathBuf::new().join(".lighthouse").join("validators"),
    )?;

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
