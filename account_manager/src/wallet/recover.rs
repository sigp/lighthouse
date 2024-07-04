use crate::wallet::create::{create_wallet_from_mnemonic, STDIN_INPUTS_FLAG};
use crate::wallet::create::{HD_TYPE, NAME_FLAG, PASSWORD_FLAG, TYPE_FLAG};
use account_utils::read_mnemonic_from_cli;
use clap::{Arg, ArgAction, ArgMatches, Command};
use std::path::PathBuf;

pub const CMD: &str = "recover";
pub const MNEMONIC_FLAG: &str = "mnemonic-path";

pub fn cli_app() -> Command {
    Command::new(CMD)
        .about("Recovers an EIP-2386 wallet from a given a BIP-39 mnemonic phrase.")
        .arg(
            Arg::new(NAME_FLAG)
                .long(NAME_FLAG)
                .value_name("WALLET_NAME")
                .help(
                    "The wallet will be created with this name. It is not allowed to \
                            create two wallets with the same name for the same --base-dir.",
                )
                .action(ArgAction::Set)
                .display_order(0),
        )
        .arg(
            Arg::new(PASSWORD_FLAG)
                .long(PASSWORD_FLAG)
                .value_name("PASSWORD_FILE_PATH")
                .help(
                    "This will be the new password for your recovered wallet. \
                    A path to a file containing the password which will unlock the wallet. \
                    If the file does not exist, a random password will be generated and \
                    saved at that path. To avoid confusion, if the file does not already \
                    exist it must include a '.pass' suffix.",
                )
                .action(ArgAction::Set)
                .display_order(0),
        )
        .arg(
            Arg::new(MNEMONIC_FLAG)
                .long(MNEMONIC_FLAG)
                .value_name("MNEMONIC_PATH")
                .help("If present, the mnemonic will be read in from this file.")
                .action(ArgAction::Set)
                .display_order(0),
        )
        .arg(
            Arg::new(TYPE_FLAG)
                .long(TYPE_FLAG)
                .value_name("WALLET_TYPE")
                .help(
                    "The type of wallet to create. Only HD (hierarchical-deterministic) \
                            wallets are supported presently..",
                )
                .action(ArgAction::Set)
                .value_parser([HD_TYPE])
                .default_value(HD_TYPE)
                .display_order(0),
        )
        .arg(
            Arg::new(STDIN_INPUTS_FLAG)
                .action(ArgAction::SetTrue)
                .hide(cfg!(windows))
                .long(STDIN_INPUTS_FLAG)
                .help("If present, read all user inputs from stdin instead of tty.")
                .display_order(0),
        )
}

pub fn cli_run(matches: &ArgMatches, wallet_base_dir: PathBuf) -> Result<(), String> {
    let mnemonic_path: Option<PathBuf> = clap_utils::parse_optional(matches, MNEMONIC_FLAG)?;
    let stdin_inputs = cfg!(windows) || matches.get_flag(STDIN_INPUTS_FLAG);

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
