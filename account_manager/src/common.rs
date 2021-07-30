use account_utils::PlainText;
use account_utils::{read_input_from_user, strip_off_newlines};
use eth2_wallet::bip39::{Language, Mnemonic};
use std::fs;
use std::path::PathBuf;
use std::str::from_utf8;
use std::thread::sleep;
use std::time::Duration;

pub const MNEMONIC_PROMPT: &str = "Enter the mnemonic phrase:";
pub const WALLET_NAME_PROMPT: &str = "Enter wallet name:";

pub fn read_mnemonic_from_cli(
    mnemonic_path: Option<PathBuf>,
    stdin_inputs: bool,
) -> Result<Mnemonic, String> {
    let mnemonic = match mnemonic_path {
        Some(path) => fs::read(&path)
            .map_err(|e| format!("Unable to read {:?}: {:?}", path, e))
            .and_then(|bytes| {
                let bytes_no_newlines: PlainText = strip_off_newlines(bytes).into();
                let phrase = from_utf8(bytes_no_newlines.as_ref())
                    .map_err(|e| format!("Unable to derive mnemonic: {:?}", e))?;
                Mnemonic::from_phrase(phrase, Language::English).map_err(|e| {
                    format!(
                        "Unable to derive mnemonic from string {:?}: {:?}",
                        phrase, e
                    )
                })
            })?,
        None => loop {
            eprintln!();
            eprintln!("{}", MNEMONIC_PROMPT);

            let mnemonic = read_input_from_user(stdin_inputs)?;

            match Mnemonic::from_phrase(mnemonic.as_str(), Language::English) {
                Ok(mnemonic_m) => {
                    eprintln!("Valid mnemonic provided.");
                    eprintln!();
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

/// Reads in a wallet name from the user. If the `--wallet-name` flag is provided, use it. Otherwise
/// read from an interactive prompt using tty unless the `--stdin-inputs` flag is provided.
pub fn read_wallet_name_from_cli(
    wallet_name: Option<String>,
    stdin_inputs: bool,
) -> Result<String, String> {
    match wallet_name {
        Some(name) => Ok(name),
        None => {
            eprintln!("{}", WALLET_NAME_PROMPT);

            read_input_from_user(stdin_inputs)
        }
    }
}
