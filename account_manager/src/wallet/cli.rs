pub use clap::Parser;
use eth2_wallet_manager::WalletType;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::create::validate_mnemonic_length;

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(about = "Manage wallets, from which validator keys can be derived.")]
#[command(next_display_order = None)]
pub struct Wallet {
    #[clap(
        long,
        value_name = "WALLETS_DIRECTORY",
        conflicts_with = "datadir",
        help = "A path containing Eth2 EIP-2386 wallets. Defaults to ~/.lighthouse/{network}/wallets"
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
#[command(next_display_order = None)]
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
    pub password_file: Option<PathBuf>,

    #[clap(
        long = "type",
        value_name = "WALLET_TYPE",
        value_enum,
        default_value_t = WalletType::Hd,
        help = "The type of wallet to create. Only HD (hierarchical-deterministic) \
                wallets are supported presently..",
    )]
    pub r#type: WalletType,

    #[clap(
        long,
        value_name = "MNEMONIC_PATH",
        help = "If present, the mnemonic will be saved to this file. DO NOT SHARE THE MNEMONIC."
    )]
    pub mnemonic_output_path: Option<PathBuf>,

    #[clap(
        long,
        value_parser = validate_mnemonic_length,
        default_value_t = 24,
        value_name = "MNEMONIC_LENGTH",
        help = "The number of words to use for the mnemonic phrase.",
    )]
    pub mnemonic_length: usize,
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(about = "Lists the names of all wallets.")]
pub struct List {}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(about = "Recovers an EIP-2386 wallet from a given a BIP-39 mnemonic phrase.")]
#[command(next_display_order = None)]
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
    pub password_file: Option<PathBuf>,

    #[clap(
        long,
        value_name = "MNEMONIC_PATH",
        help = "If present, the mnemonic will be read in from this file."
    )]
    pub mnemonic_path: Option<PathBuf>,

    #[clap(
        long = "type",
        value_name = "WALLET_TYPE",
        value_enum,
        default_value_t = WalletType::Hd,
        help = "The type of wallet to create. Only HD (hierarchical-deterministic) \
                wallets are supported presently..",
    )]
    pub r#type: WalletType,
}

