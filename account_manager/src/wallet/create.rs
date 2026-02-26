use crate::WALLETS_DIR_FLAG;
use crate::common::read_wallet_name_from_cli;
use account_utils::{
    PlainText, STDIN_INPUTS_FLAG, is_password_sufficiently_complex, random_password,
    read_password_from_user, strip_off_newlines,
};
use clap::ArgMatches;
use eth2_wallet::bip39::{Language, Mnemonic, MnemonicType};
use eth2_wallet_manager::{LockedWallet, WalletManager, WalletType};
use filesystem::create_with_600_perms;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use super::cli::{Create, Recover};

pub const CMD: &str = "create";
pub const HD_TYPE: &str = "hd";
pub const NEW_WALLET_PASSWORD_PROMPT: &str =
    "Enter a password for your new wallet that is at least 12 characters long:";
pub const RETYPE_PASSWORD_PROMPT: &str = "Please re-enter your wallet's new password:";

pub const MNEMONIC_TYPES: &[MnemonicType] = &[
    MnemonicType::Words12,
    MnemonicType::Words15,
    MnemonicType::Words18,
    MnemonicType::Words21,
    MnemonicType::Words24,
];

pub fn cli_run(
    create_config: &Create,
    matches: &ArgMatches,
    wallet_base_dir: PathBuf,
) -> Result<(), String> {
    let mnemonic_output_path = create_config.mnemonic_output_path.clone();

    // Create a new random mnemonic.
    //
    // The `tiny-bip39` crate uses `thread_rng()` for this entropy.
    let mnemonic_length = create_config.mnemonic_length;
    let mnemonic = Mnemonic::new(
        MnemonicType::for_word_count(mnemonic_length).expect("Mnemonic length already validated"),
        Language::English,
    );

    let wallet =
        create_config.create_wallet_from_mnemonic(wallet_base_dir.as_path(), matches, &mnemonic)?;

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
                PlainText::from(read_password_from_user(stdin_inputs)?.as_bytes().to_vec());

            // Ensure the password meets the minimum requirements.
            match is_password_sufficiently_complex(password.as_bytes()) {
                Ok(_) => {
                    eprintln!("{}", RETYPE_PASSWORD_PROMPT);
                    let retyped_password =
                        PlainText::from(read_password_from_user(stdin_inputs)?.as_bytes().to_vec());
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

pub fn validate_mnemonic_length(len: &str) -> Result<usize, String> {
    match len.parse::<usize>().ok().and_then(|words| {
        if MnemonicType::for_word_count(words).is_ok() {
            Some(words)
        } else {
            None
        }
    }) {
        Some(words) => Ok(words),
        None => Err(format!(
            "Mnemonic length must be one of {}",
            MNEMONIC_TYPES
                .iter()
                .map(|t| t.word_count().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

pub trait NewWallet {
    fn get_name(&self) -> Option<String>;
    fn get_password(&self) -> Option<PathBuf>;
    fn get_type(&self) -> WalletType;
    fn create_wallet_from_mnemonic(
        &self,
        wallet_base_dir: &Path,
        matches: &ArgMatches,
        mnemonic: &Mnemonic,
    ) -> Result<LockedWallet, String> {
        let name: Option<String> = self.get_name();
        let wallet_password_path: Option<PathBuf> = self.get_password();
        let wallet_type: WalletType = self.get_type();
        let stdin_inputs = cfg!(windows) || matches.get_flag(STDIN_INPUTS_FLAG);

        let mgr = WalletManager::open(wallet_base_dir)
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
}

impl NewWallet for Create {
    fn get_name(&self) -> Option<String> {
        self.name.clone()
    }
    fn get_password(&self) -> Option<PathBuf> {
        self.password_file.clone()
    }
    fn get_type(&self) -> WalletType {
        self.r#type
    }
}

impl NewWallet for Recover {
    fn get_name(&self) -> Option<String> {
        self.name.clone()
    }
    fn get_password(&self) -> Option<PathBuf> {
        self.password_file.clone()
    }
    fn get_type(&self) -> WalletType {
        self.r#type
    }
}
