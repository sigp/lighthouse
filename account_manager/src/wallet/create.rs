use crate::common::read_wallet_name_from_cli;
use crate::WALLETS_DIR_FLAG;
use account_utils::{
    is_password_sufficiently_complex, random_password, read_password_from_user, strip_off_newlines,
};
use clap::{App, Arg, ArgMatches};
use eth2_wallet::{
    bip39::{Language, Mnemonic, MnemonicType},
    PlainText,
};
use eth2_wallet_manager::{LockedWallet, WalletManager, WalletType};
use filesystem::create_with_600_perms;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

pub const CMD: &str = "create";
pub const HD_TYPE: &str = "hd";
pub const NAME_FLAG: &str = "name";
pub const PASSWORD_FLAG: &str = "password-file";
pub const TYPE_FLAG: &str = "type";
pub const MNEMONIC_FLAG: &str = "mnemonic-output-path";
pub const STDIN_INPUTS_FLAG: &str = "stdin-inputs";
pub const MNEMONIC_LENGTH_FLAG: &str = "mnemonic-length";
pub const MNEMONIC_TYPES: &[MnemonicType] = &[
    MnemonicType::Words12,
    MnemonicType::Words15,
    MnemonicType::Words18,
    MnemonicType::Words21,
    MnemonicType::Words24,
];
pub const NEW_WALLET_PASSWORD_PROMPT: &str =
    "Enter a password for your new wallet that is at least 12 characters long:";
pub const RETYPE_PASSWORD_PROMPT: &str = "Please re-enter your wallet's new password:";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about("Creates a new HD (hierarchical-deterministic) EIP-2386 wallet.")
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
                .value_name("WALLET_PASSWORD_PATH")
                .help(
                    "A path to a file containing the password which will unlock the wallet. \
                    If the file does not exist, a random password will be generated and \
                    saved at that path. To avoid confusion, if the file does not already \
                    exist it must include a '.pass' suffix.",
                )
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
            Arg::with_name(MNEMONIC_FLAG)
                .long(MNEMONIC_FLAG)
                .value_name("MNEMONIC_PATH")
                .help(
                    "If present, the mnemonic will be saved to this file. DO NOT SHARE THE MNEMONIC.",
                )
                .takes_value(true)
        )
        .arg(
            Arg::with_name(STDIN_INPUTS_FLAG)
                .takes_value(false)
                .hidden(cfg!(windows))
                .long(STDIN_INPUTS_FLAG)
                .help("If present, read all user inputs from stdin instead of tty."),
        )
        .arg(
            Arg::with_name(MNEMONIC_LENGTH_FLAG)
                .long(MNEMONIC_LENGTH_FLAG)
                .value_name("MNEMONIC_LENGTH")
                .help("The number of words to use for the mnemonic phrase.")
                .takes_value(true)
                .validator(|len| {
                    match len.parse::<usize>().ok().and_then(|words| MnemonicType::for_word_count(words).ok()) {
                        Some(_) => Ok(()),
                        None => Err(format!("Mnemonic length must be one of {}", MNEMONIC_TYPES.iter().map(|t| t.word_count().to_string()).collect::<Vec<_>>().join(", "))),
                    }
                })
                .default_value("24"),
        )
}

pub fn cli_run(matches: &ArgMatches, wallet_base_dir: PathBuf) -> Result<(), String> {
    let mnemonic_output_path: Option<PathBuf> = clap_utils::parse_optional(matches, MNEMONIC_FLAG)?;

    // Create a new random mnemonic.
    //
    // The `tiny-bip39` crate uses `thread_rng()` for this entropy.
    let mnemonic_length = clap_utils::parse_required(matches, MNEMONIC_LENGTH_FLAG)?;
    let mnemonic = Mnemonic::new(
        MnemonicType::for_word_count(mnemonic_length).expect("Mnemonic length already validated"),
        Language::English,
    );

    let wallet = create_wallet_from_mnemonic(matches, wallet_base_dir.as_path(), &mnemonic)?;

    if let Some(path) = mnemonic_output_path {
        create_with_600_perms(&path, mnemonic.phrase().as_bytes())
            .map_err(|e| format!("Unable to write mnemonic to {:?}: {:?}", path, e))?;
    }

    println!("Your wallet's {}-word BIP-39 mnemonic is:", mnemonic_length);
    println!();
    println!("\t{}", mnemonic.phrase());
    println!();
    println!("This mnemonic can be used to fully restore your wallet, should ");
    println!("you lose the JSON file or your password. ");
    println!();
    println!("It is very important that you DO NOT SHARE this mnemonic as it will ");
    println!("reveal the private keys of all validators and keys generated with  ");
    println!("this wallet. That would be catastrophic.");
    println!();
    println!("It is also important to store a backup of this mnemonic so you can ");
    println!("recover your private keys in the case of data loss. Writing it on ");
    println!("a piece of paper and storing it in a safe place would be prudent.");
    println!();
    println!("Your wallet's UUID is:");
    println!();
    println!("\t{}", wallet.wallet().uuid());
    println!();
    println!("You do not need to backup your UUID or keep it secret.");

    Ok(())
}

pub fn create_wallet_from_mnemonic(
    matches: &ArgMatches,
    wallet_base_dir: &Path,
    mnemonic: &Mnemonic,
) -> Result<LockedWallet, String> {
    let name: Option<String> = clap_utils::parse_optional(matches, NAME_FLAG)?;
    let wallet_password_path: Option<PathBuf> = clap_utils::parse_optional(matches, PASSWORD_FLAG)?;
    let type_field: String = clap_utils::parse_required(matches, TYPE_FLAG)?;
    let stdin_inputs = cfg!(windows) || matches.is_present(STDIN_INPUTS_FLAG);
    let wallet_type = match type_field.as_ref() {
        HD_TYPE => WalletType::Hd,
        unknown => return Err(format!("--{} {} is not supported", TYPE_FLAG, unknown)),
    };

    let mgr = WalletManager::open(&wallet_base_dir)
        .map_err(|e| format!("Unable to open --{}: {:?}", WALLETS_DIR_FLAG, e))?;

    let wallet_password: PlainText = match wallet_password_path {
        Some(path) => {
            // Create a random password if the file does not exist.
            if !path.exists() {
                // To prevent users from accidentally supplying their password to the PASSWORD_FLAG and
                // create a file with that name, we require that the password has a .pass suffix.
                if path.extension() != Some(OsStr::new("pass")) {
                    return Err(format!(
                        "Only creates a password file if that file ends in .pass: {:?}",
                        path
                    ));
                }

                create_with_600_perms(&path, random_password().as_bytes())
                    .map_err(|e| format!("Unable to write to {:?}: {:?}", path, e))?;
            }
            read_new_wallet_password_from_cli(Some(path), stdin_inputs)?
        }
        None => read_new_wallet_password_from_cli(None, stdin_inputs)?,
    };

    let wallet_name = read_wallet_name_from_cli(name, stdin_inputs)?;

    let wallet = mgr
        .create_wallet(
            wallet_name,
            wallet_type,
            mnemonic,
            wallet_password.as_bytes(),
        )
        .map_err(|e| format!("Unable to create wallet: {:?}", e))?;
    Ok(wallet)
}

/// Used when a user is creating a new wallet. Read in a wallet password from a file if the password file
/// path is provided. Otherwise, read from an interactive prompt using tty unless the `--stdin-inputs`
/// flag is provided. This verifies the password complexity and verifies the password is correctly re-entered.
pub fn read_new_wallet_password_from_cli(
    password_file_path: Option<PathBuf>,
    stdin_inputs: bool,
) -> Result<PlainText, String> {
    match password_file_path {
        Some(path) => {
            let password: PlainText = fs::read(&path)
                .map_err(|e| format!("Unable to read {:?}: {:?}", path, e))
                .map(|bytes| strip_off_newlines(bytes).into())?;

            // Ensure the password meets the minimum requirements.
            is_password_sufficiently_complex(password.as_bytes())?;
            Ok(password)
        }
        None => loop {
            eprintln!();
            eprintln!("{}", NEW_WALLET_PASSWORD_PROMPT);
            let password =
                PlainText::from(read_password_from_user(stdin_inputs)?.as_ref().to_vec());

            // Ensure the password meets the minimum requirements.
            match is_password_sufficiently_complex(password.as_bytes()) {
                Ok(_) => {
                    eprintln!("{}", RETYPE_PASSWORD_PROMPT);
                    let retyped_password =
                        PlainText::from(read_password_from_user(stdin_inputs)?.as_ref().to_vec());
                    if retyped_password == password {
                        break Ok(password);
                    } else {
                        eprintln!("Passwords do not match.");
                    }
                }
                Err(message) => eprintln!("{}", message),
            }
        },
    }
}
