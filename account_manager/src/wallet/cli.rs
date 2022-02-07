use crate::common::read_wallet_name_from_cli;
use crate::wallet::create::HD_TYPE;
use crate::wallet::create::{read_new_wallet_password_from_cli, validate_mnemonic_length};
use crate::WALLETS_DIR_FLAG;
use account_utils::{random_password, PlainText};
pub use clap::{IntoApp, Parser};
use eth2_wallet::bip39::Mnemonic;
use eth2_wallet_manager::{LockedWallet, WalletManager, WalletType};
use filesystem::create_with_600_perms;
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(about = "Manage wallets, from which validator keys can be derived.")]
pub struct Wallet {
    #[clap(
        long,
        value_name = "WALLETS_DIRECTORY",
        help = "A path containing Eth2 EIP-2386 wallets. Defaults to ~/.lighthouse/{network}/wallets",
        conflicts_with = "datadir"
    )]
    pub wallets_dir: Option<PathBuf>,
    #[clap(subcommand)]
    pub subcommand: WalletSubcommand,
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
pub enum WalletSubcommand {
    Create(Create),
    List(List),
    Recover(Recover),
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(about = "Creates a new HD (hierarchical-deterministic) EIP-2386 wallet.")]
pub struct Create {
    #[clap(
        long,
        value_name = "WALLET_NAME",
        help = "The wallet will be created with this name. It is not allowed to \
                            create two wallets with the same name for the same --base-dir."
    )]
    pub name: Option<String>,
    #[clap(
        long,
        value_name = "WALLET_PASSWORD_PATH",
        help = "A path to a file containing the password which will unlock the wallet. \
                    If the file does not exist, a random password will be generated and \
                    saved at that path. To avoid confusion, if the file does not already \
                    exist it must include a '.pass' suffix."
    )]
    pub password: Option<PathBuf>,
    #[clap(
    long,
    value_name = "WALLET_TYPE",
    help =
    "The type of wallet to create. Only HD (hierarchical-deterministic) \
                            wallets are supported presently..",

    possible_values = &[HD_TYPE],
    default_value = HD_TYPE,
    name = "type")]
    pub create_type: WalletType,
    #[clap(
        long,
        value_name = "MNEMONIC_PATH",
        help = "If present, the mnemonic will be saved to this file. DO NOT SHARE THE MNEMONIC."
    )]
    pub mnemonic: Option<PathBuf>,
    #[clap(
    hide = cfg!(windows),
    long,
    help = "If present, read all user inputs from stdin instead of tty.",)]
    pub stdin_inputs: bool,
    #[clap(                long,
    value_name = "MNEMONIC_LENGTH",
    help = "The number of words to use for the mnemonic phrase.",
    validator = validate_mnemonic_length,
    default_value_t = 24)]
    pub mnemonic_length: usize,
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(about = "Lists the names of all wallets.")]
pub struct List {}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(about = "Recovers an EIP-2386 wallet from a given a BIP-39 mnemonic phrase.")]
pub struct Recover {
    #[clap(
        long,
        value_name = "WALLET_NAME",
        help = "The wallet will be created with this name. It is not allowed to \
                            create two wallets with the same name for the same --base-dir."
    )]
    pub name: Option<String>,
    #[clap(
        long,
        value_name = "PASSWORD_FILE_PATH",
        help = "This will be the new password for your recovered wallet. \
                    A path to a file containing the password which will unlock the wallet. \
                    If the file does not exist, a random password will be generated and \
                    saved at that path. To avoid confusion, if the file does not already \
                    exist it must include a '.pass' suffix."
    )]
    pub password: Option<PathBuf>,
    #[clap(
        long,
        value_name = "MNEMONIC_PATH",
        help = "If present, the mnemonic will be read in from this file."
    )]
    pub mnemonic: Option<PathBuf>,
    #[clap(                long,
    value_name = "WALLET_TYPE",
    help =
    "The type of wallet to create. Only HD (hierarchical-deterministic) \
                            wallets are supported presently..",
    possible_values = &[HD_TYPE],
    default_value = HD_TYPE,
    name = "type")]
    pub recover_type: WalletType,
    #[clap(
    hide = cfg!(windows),
    long,
    help = "If present, read all user inputs from stdin instead of tty.",)]
    pub stdin_inputs: bool,
}

pub trait NewWallet {
    fn get_name(&self) -> Option<String>;
    fn get_password(&self) -> Option<PathBuf>;
    fn get_type(&self) -> WalletType;
    fn is_stdin_inputs(&self) -> bool;
    fn create_wallet_from_mnemonic(
        &self,
        wallet_base_dir: &Path,
        mnemonic: &Mnemonic,
    ) -> Result<LockedWallet, String> {
        let name: Option<String> = self.get_name();
        let wallet_password_path: Option<PathBuf> = self.get_password();
        let wallet_type: WalletType = self.get_type();
        let stdin_inputs = cfg!(windows) || self.is_stdin_inputs();

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
}

impl NewWallet for Create {
    fn get_name(&self) -> Option<String> {
        self.name.clone()
    }
    fn get_password(&self) -> Option<PathBuf> {
        self.password.clone()
    }
    fn get_type(&self) -> WalletType {
        self.create_type.clone()
    }
    fn is_stdin_inputs(&self) -> bool {
        self.stdin_inputs
    }
}

impl NewWallet for Recover {
    fn get_name(&self) -> Option<String> {
        self.name.clone()
    }
    fn get_password(&self) -> Option<PathBuf> {
        self.password.clone()
    }
    fn get_type(&self) -> WalletType {
        self.recover_type.clone()
    }
    fn is_stdin_inputs(&self) -> bool {
        self.stdin_inputs
    }
}
