use crate::common::read_mnemonic_from_cli;
use crate::wallet::create::{create_wallet_from_mnemonic, STDIN_INPUTS_FLAG};
use crate::wallet::create::{HD_TYPE, NAME_FLAG, PASSWORD_FLAG, TYPE_FLAG};
use clap::{App, Arg, ArgMatches};
use std::path::PathBuf;

pub const CMD: &str = "recover";
pub const MNEMONIC_FLAG: &str = "mnemonic-path";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about("Recovers an EIP-2386 wallet from a given a BIP-39 mnemonic phrase.")
        .arg(
            Arg::with_name(NAME_FLAG)
                .long(NAME_FLAG)
                .value_name("WALLET_NAME")
                .help(
                    "The wallet will be created with this name. It is not allowed to \
                            create two wallets with the same name for the same --base-dir.",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name(PASSWORD_FLAG)
                .long(PASSWORD_FLAG)
                .value_name("PASSWORD_FILE_PATH")
                .help(
                    "This will be the new password for your recovered wallet. \
                    A path to a file containing the password which will unlock the wallet. \
                    If the file does not exist, a random password will be generated and \
                    saved at that path. To avoid confusion, if the file does not already \
                    exist it must include a '.pass' suffix.",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name(MNEMONIC_FLAG)
                .long(MNEMONIC_FLAG)
                .value_name("MNEMONIC_PATH")
                .help("If present, the mnemonic will be read in from this file.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name(TYPE_FLAG)
                .long(TYPE_FLAG)
                .value_name("WALLET_TYPE")
                .help(
                    "The type of wallet to create. Only HD (hierarchical-deterministic) \
                            wallets are supported presently..",
                )
                .takes_value(true)
                .possible_values(&[HD_TYPE])
                .default_value(HD_TYPE),
        )
        .arg(
            Arg::with_name(STDIN_INPUTS_FLAG)
                .takes_value(false)
                .hidden(cfg!(windows))
                .long(STDIN_INPUTS_FLAG)
                .help("If present, read all user inputs from stdin instead of tty."),
        )
}

pub fn cli_run(matches: &ArgMatches, wallet_base_dir: PathBuf) -> Result<(), String> {
    let mnemonic_path: Option<PathBuf> = clap_utils::parse_optional(matches, MNEMONIC_FLAG)?;
    let stdin_inputs = cfg!(windows) || matches.is_present(STDIN_INPUTS_FLAG);

    eprintln!();
    eprintln!("WARNING: KEY RECOVERY CAN LEAD TO DUPLICATING VALIDATORS KEYS, WHICH CAN LEAD TO SLASHING.");
    eprintln!();

    let mnemonic = read_mnemonic_from_cli(mnemonic_path, stdin_inputs)?;

    let wallet = create_wallet_from_mnemonic(matches, wallet_base_dir.as_path(), &mnemonic)
        .map_err(|e| format!("Unable to create wallet: {:?}", e))?;

    println!("Your wallet has been successfully recovered.");
    println!();
    println!("Your wallet's UUID is:");
    println!();
    println!("\t{}", wallet.wallet().uuid());
    println!();
    println!("You do not need to backup your UUID or keep it secret.");

    Ok(())
}
