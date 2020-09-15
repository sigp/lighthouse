use account_utils::{MINIMUM_PASSWORD_LEN, PlainText, read_password_from_user, ZeroizeString, is_password_sufficiently_complex};
use account_utils::{read_input_from_user, strip_off_newlines};
use clap::ArgMatches;
use eth2_wallet::bip39::{Language, Mnemonic};
use std::fs;
use std::fs::create_dir_all;
use std::path::{Path, PathBuf};
use std::str::from_utf8;
use std::thread::sleep;
use std::time::Duration;

pub const MNEMONIC_PROMPT: &str = "Enter the mnemonic phrase:";
pub const WALLET_NAME_PROMPT: &str = "Enter a name for your wallet:";
pub const WALLET_PASSWORD_PROMPT: &str = "Enter your wallet's password:";
pub const RETYPE_PASSWORD_PROMPT: &str = "Please re-enter your wallet's password:";

pub fn ensure_dir_exists<P: AsRef<Path>>(path: P) -> Result<(), String> {
    let path = path.as_ref();

    if !path.exists() {
        create_dir_all(path).map_err(|e| format!("Unable to create {:?}: {:?}", path, e))?;
    }

    Ok(())
}

pub fn base_wallet_dir(matches: &ArgMatches, arg: &'static str) -> Result<PathBuf, String> {
    clap_utils::parse_path_with_default_in_home_dir(
        matches,
        arg,
        PathBuf::new().join(".lighthouse").join("wallets"),
    )
}

pub fn read_mnemonic_from_cli(
    mnemonic_path: Option<PathBuf>,
    stdin_inputs: bool,
) -> Result<Mnemonic, String> {
    let mnemonic = match mnemonic_path {
        Some(path) => fs::read(&path)
            .map_err(|e| format!("Unable to read {:?}: {:?}", path, e))
            .and_then(|bytes| {
                let bytes_no_newlines: PlainText = strip_off_newlines(bytes).into();
                let phrase = from_utf8(&bytes_no_newlines.as_ref())
                    .map_err(|e| format!("Unable to derive mnemonic: {:?}", e))?;
                Mnemonic::from_phrase(phrase, Language::English).map_err(|e| {
                    format!(
                        "Unable to derive mnemonic from string {:?}: {:?}",
                        phrase, e
                    )
                })
            })?,
        None => loop {
            eprintln!("");
            eprintln!("{}", MNEMONIC_PROMPT);

            let mnemonic = read_input_from_user(stdin_inputs)?;

            match Mnemonic::from_phrase(mnemonic.as_str(), Language::English) {
                Ok(mnemonic_m) => {
                    eprintln!("Valid mnemonic provided.");
                    eprintln!("");
                    sleep(Duration::from_secs(1));
                    break mnemonic_m;
                }
                Err(_) => {
                    eprintln!("Invalid mnemonic");
                }
            }
        },
    };
    Ok(mnemonic)
}

pub fn read_wallet_password_from_cli(
    password_file_path: Option<PathBuf>,
    stdin_inputs: bool
) -> Result<PlainText, String> {
    match password_file_path {
        Some(path) => {
            let password = fs::read(&path)
                .map_err(|e| format!("Unable to read {:?}: {:?}", path, e))
                .map(|bytes|
                    strip_off_newlines(bytes).into());
            if is_password_sufficiently_complex(password.as_bytes()) {
                password
            } else {
                Err(format!("Please use at least {} characters for your password.", MINIMUM_PASSWORD_LEN))
            }
        }
        None => {
            loop {
                eprintln!("");
                eprintln!("{}", WALLET_PASSWORD_PROMPT);
                let password = PlainText::from(read_password_from_user(stdin_inputs)?.as_ref().into_vec());
                if is_password_sufficiently_complex(password.as_bytes()) {
                    eprintln!("{}", RETYPE_PASSWORD_PROMPT);
                    let retyped_password = PlainText::from(read_password_from_user(stdin_inputs)?.as_ref().into_vec());
                    if retyped_password == password {
                        break password;
                    } else {
                        eprintln!("Passwords do not match.");
                    }
                } else {
                    eprintln!("Please use at least {} characters for your password.", MINIMUM_PASSWORD_LEN);
                }
            }
        }
    }
}

pub fn read_wallet_name_from_cli(
    wallet_name: Option<String>,
    stdin_inputs: bool,
) -> Result<String, String> {
    match wallet_name {
        Some(name) => Ok(name),
        None => {
            eprintln!("");
            eprintln!("{}", WALLET_NAME_PROMPT);

            read_input_from_user(stdin_inputs)
        }
    }
}
