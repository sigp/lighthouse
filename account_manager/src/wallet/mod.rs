mod create;

use crate::common::{base_wallet_dir, ensure_dir_exists};
use clap::{App, Arg, ArgMatches};
use environment::Environment;
use types::EthSpec;

pub const CMD: &str = "wallet";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about("TODO")
        .arg(
            Arg::with_name("base-dir")
                .long("base-dir")
                .value_name("BASE_DIRECTORY")
                .help("A path containing Eth2 EIP-2386 wallets. Defaults to ~/.lighthouse/wallets")
                .takes_value(true),
        )
        .subcommand(create::cli_app())
}

pub fn cli_run<T: EthSpec>(matches: &ArgMatches, env: Environment<T>) -> Result<(), String> {
    let base_dir = base_wallet_dir(matches, "base-dir")?;
    ensure_dir_exists(&base_dir)?;

    match matches.subcommand() {
        (create::CMD, Some(matches)) => create::cli_run::<T>(matches, base_dir),
        (unknown, _) => {
            return Err(format!(
                "{} does not have a {} command. See --help",
                CMD, unknown
            ));
        }
    }
}
