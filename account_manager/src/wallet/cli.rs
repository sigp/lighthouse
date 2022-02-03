use clap::{ArgEnum, Args, Subcommand};
pub use clap::{IntoApp, Parser};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(about = "Manage wallets, from which validator keys can be derived.")]
pub struct Wallet {
    #[clap(
        long,
        value_name = "WALLETS_DIRECTORY",
        help = "A path containing Eth2 EIP-2386 wallets. Defaults to ~/.lighthouse/{network}/wallets",
        takes_value = true,
        conflicts_with = "datadir"
    )]
    pub wallets_dir: Option<String>,
    subcommand: WalletSubcommand,
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
                            create two wallets with the same name for the same --base-dir.",
        takes_value = true
    )]
    pub name: Option<String>,
    #[clap(
        long,
        value_name = "WALLET_PASSWORD_PATH",
        help = "A path to a file containing the password which will unlock the wallet. \
                    If the file does not exist, a random password will be generated and \
                    saved at that path. To avoid confusion, if the file does not already \
                    exist it must include a '.pass' suffix.",
        takes_value = true
    )]
    pub password: Option<String>,
    #[clap(
    long,
    value_name = "WALLET_TYPE",
    help =
    "The type of wallet to create. Only HD (hierarchical-deterministic) \
                            wallets are supported presently..",

    takes_value = true,
    possible_values = &[HD_TYPE],
    default_value = HD_TYPE,
    rename = "type")]
    pub create_type: Option<String>,
    #[clap(
        long,
        value_name = "MNEMONIC_PATH",
        help = "If present, the mnemonic will be saved to this file. DO NOT SHARE THE MNEMONIC.",
        takes_value = true
    )]
    pub mnemonic: Option<String>,
    #[clap(
    takes_value = false,
    hide = cfg!(windows),
    long,
    help = "If present, read all user inputs from stdin instead of tty.",)]
    pub stdin_inputs: Option<String>,
    #[clap(                long,
    value_name = "MNEMONIC_LENGTH",
    help = "The number of words to use for the mnemonic phrase.",
    takes_value = true,
    validator = |len| {
    match len.parse::<usize>().ok().and_then(|words| MnemonicType::for_word_count(words).ok()) {
    Some(_) => Ok(()),
    None => Err(format!("Mnemonic length must be one of {}", MNEMONIC_TYPES.iter().map(|t| t.word_count().to_string()).collect::<Vec<_>>().join(", "))),
    }
    }
    ,
    default_value = "24",)]
    pub mnemonic_length: Option<String>,
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
                            create two wallets with the same name for the same --base-dir.",
        takes_value = true
    )]
    pub name: Option<String>,
    #[clap(
        long,
        value_name = "PASSWORD_FILE_PATH",
        help = "This will be the new password for your recovered wallet. \
                    A path to a file containing the password which will unlock the wallet. \
                    If the file does not exist, a random password will be generated and \
                    saved at that path. To avoid confusion, if the file does not already \
                    exist it must include a '.pass' suffix.",
        takes_value = true
    )]
    pub password: Option<String>,
    #[clap(
        long,
        value_name = "MNEMONIC_PATH",
        help = "If present, the mnemonic will be read in from this file.",
        takes_value = true
    )]
    pub mnemonic: Option<String>,
    #[clap(                long,
    value_name = "WALLET_TYPE",
    help =
    "The type of wallet to create. Only HD (hierarchical-deterministic) \
                            wallets are supported presently..",
    takes_value = true,
    possible_values = &[HD_TYPE],
    default_value = HD_TYPE,
    rename = "type")]
    pub recover_type: Option<String>,
    #[clap(                takes_value = false,
    hide = cfg!(windows),
    long,
    help = "If present, read all user inputs from stdin instead of tty.",)]
    pub stdin_inputs: Option<String>,
}
