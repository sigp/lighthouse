use account_utils::PlainText;
use account_utils::{read_mnemonic_from_user, strip_off_newlines};
use clap::ArgMatches;
use eth2_wallet::bip39::{Language, Mnemonic};
use std::fs;
use std::fs::create_dir_all;
use std::path::{Path, PathBuf};
use std::str::from_utf8;
use std::thread::sleep;
use std::time::Duration;

pub const MNEMONIC_PROMPT: &str = "Enter the mnemonic phrase:";

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
    stdin_password: bool,
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

            let mnemonic = read_mnemonic_from_user(stdin_password)?;

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
