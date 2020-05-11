use clap::{App, Arg, ArgMatches};
use std::path::PathBuf;
use types::EthSpec;

pub const CMD: &str = "validator";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about("Creates new validators from an existing wallet located in --base-dir.")
        .arg(
            Arg::with_name("name")
                .long("name")
                .value_name("WALLET_NAME")
                .help("Use the wallet identified by this name")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("wallet-password")
                .long("wallet-passphrase")
                .value_name("WALLET_PASSWORD_PATH")
                .help("A path to a file containing the password which will unlock the wallet.")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("validator-dir")
                .long("validator-dir")
                .value_name("VALIDATOR_DIRECTORY")
                .help(
                    "The path where the validator directories will be created. \
                            Defaults to ~/.lighthouse/validators",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("deposit-gwei")
                .long("deposit-gwei")
                .value_name("DEPOSIT_GWEI")
                .help(
                    "The GWEI value of the deposit amount. Defaults to the minimum amount
                            required for an active validator (MAX_EFFECTIVE_BALANCE)",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("count")
                .long("count")
                .value_name("VALIDATOR_COUNT")
                .help("The number of validators to create, regardless of how many already exist")
                .conflicts_with("at-most")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("at-most")
                .long("at-most")
                .value_name("AT_MOST_VALIDATORS")
                .help(
                    "Observe the number of validators in --validator-dir, only creating enough to
                        ensure reach the given count. Never deletes an existing validator.",
                )
                .conflicts_with("count")
                .takes_value(true),
        )
}

pub fn cli_run<T: EthSpec>(matches: &ArgMatches, base_dir: PathBuf) -> Result<(), String> {
    todo!()
}
