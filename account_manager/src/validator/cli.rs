use clap::{ArgEnum, Args, Subcommand};
pub use clap::{IntoApp, Parser};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use bls::PublicKey;

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(about = "Provides commands for managing Eth2 validators.")]
pub struct Validator {
    #[clap(
        long,
        value_name = "VALIDATOR_DIRECTORY",
        help = "The path to search for validator directories. \
                    Defaults to ~/.lighthouse/{network}/validators",
        takes_value = true,
        conflicts_with = "datadir"
    )]
    pub validator_dir: Option<PathBuf>,
    pub subcommand: ValidatorSubcommand,
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(rename_all = "snake_case")]
pub enum ValidatorSubcommand {
    Create(Create),
    Modify(Modify),
    Import(Import),
    List(List),
    Recover(Recover),
    SlashingProtection(SlashingProtection),
    Exit(Exit),
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(
    about = "Creates new validators from an existing EIP-2386 wallet using the EIP-2333 HD key \
derivation scheme."
)]
pub struct Create {
    #[clap(
        long,
        value_name = "WALLET_NAME",
        help = "Use the wallet identified by this name",
    )]
    pub wallet_name: Option<String>,
    #[clap(
        long,
        value_name = "WALLET_PASSWORD_PATH",
        help = "A path to a file containing the password which will unlock the wallet.",
    )]
    pub wallet_password: Option<PathBuf>,
    #[clap(                long,
    value_name = WALLETS_DIR_FLAG,
    help = "A path containing Eth2 EIP-2386 wallets. Defaults to ~/.lighthouse/{network}/wallets",
    conflicts_with = "datadir",)]
    pub wallets_dir: Option<PathBuf>,
    #[clap(
        long,
        value_name = "SECRETS_DIR",
        help = "The path where the validator keystore passwords will be stored. \
                    Defaults to ~/.lighthouse/{network}/secrets",
        conflicts_with = "datadir",
    )]
    pub secrets_dir: Option<PathBuf>,
    #[clap(
        long,
        value_name = "DEPOSIT_GWEI",
        help = "The GWEI value of the deposit amount. Defaults to the minimum amount \
                    required for an active validator (MAX_EFFECTIVE_BALANCE)",
    )]
    pub deposit_gwei: Option<u64>,
    #[clap(
        long,
        help = "If present, the withdrawal keystore will be stored alongside the voting \
                    keypair. It is generally recommended to *not* store the withdrawal key and \
                    instead generate them from the wallet seed when required."
    )]
    pub store_withdraw: bool,
    #[clap(
        long,
        value_name = "VALIDATOR_COUNT",
        help = "The number of validators to create, regardless of how many already exist",
        conflicts_with = "at-most",
    )]
    pub count: Option<usize>,
    #[clap(
        long,
        value_name = "AT_MOST_VALIDATORS",
        help = "Observe the number of validators in --validator-dir, only creating enough to \
                    reach the given count. Never deletes an existing validator.",
        conflicts_with = "count",
    )]
    pub at_most: Option<usize>,
    #[clap(
    hide = cfg!(windows),
    long,
    help = "If present, read all user inputs from stdin instead of tty.",
    )]
    pub stdin_inputs: bool,
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(about = "Modify validator status in validator_definitions.yml.")]
#[clap(rename_all = "snake_case")]
pub enum Modify {
    Enable(Enable),
    Disable(Disable),
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(about = "Enable validator(s) in validator_definitions.yml.")]
pub struct Enable {
    #[clap(long, value_name = "PUBKEY", help = "Validator pubkey to enable")]
    pub pubkey: Option<PublicKey>,
    #[clap(
        long,
        help = "Enable all validators in the validator directory",
        conflicts_with = "pubkey"
    )]
    pub all: bool,
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(about = "Disable validator(s) in validator_definitions.yml.")]
pub struct Disable {
    #[clap(long, value_name = "PUBKEY", help = "Validator pubkey to disable")]
    pub pubkey: Option<PublicKey>,
    #[clap(
        long,
        help = "Disable all validators in the validator directory",
        conflicts_with = "pubkey"
    )]
    pub all: bool,
}

pub trait Modifiable {
    fn get_pubkey(&self) -> Option<PublicKey>;
    fn is_all(&self) -> bool;
}

impl Modifiable for &Enable {
    fn get_pubkey(&self) -> Option<PublicKey> {
        self.pubkey.clone()
    }
    fn is_all(&self) -> bool {
        self.all
    }
}

impl Modifiable for &Disable {
    fn get_pubkey(&self) -> Option<PublicKey> {
        self.pubkey.clone()
    }
    fn is_all(&self) -> bool {
        self.all
    }
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(
    about = "Imports one or more EIP-2335 passwords into a Lighthouse VC directory, \
            requesting passwords interactively. The directory flag provides a convenient \
            method for importing a directory of keys generated by the eth2-deposit-cli \
            Python utility."
)]
pub struct Import {
    #[clap(
        long,
        value_name = "KEYSTORE_PATH",
        help = "Path to a single keystore to be imported.",
        conflicts_with = "dir",
        required_unless_present = "dir"
    )]
    pub keystore: Option<PathBuf>,
    #[clap(
        long,
        value_name = "KEYSTORES_DIRECTORY",
        help = "Path to a directory which contains zero or more keystores \
                    for import. This directory and all sub-directories will be \
                    searched and any file name which contains 'keystore' and \
                    has the '.json' extension will be attempted to be imported.",
        conflicts_with = "keystore",
        required_unless_present = "keystore"
    )]
    pub dir: Option<PathBuf>,
    #[clap(                takes_value = false,
    hide = cfg!(windows),
    long,
    help = "If present, read all user inputs from stdin instead of tty.",)]
    pub stdin_inputs: bool,
    #[clap(
        long,
        help = "If present, the same password will be used for all imported keystores."
    )]
    pub reuse_password: bool,
    #[clap(
        long,
        value_name = "KEYSTORE_PASSWORD_PATH",
        requires = "reuse_password",
        help = "The path to the file containing the password which will unlock all \
                    keystores being imported. This flag must be used with `--reuse-password`. \
                    The password will be copied to the `validator_definitions.yml` file, so after \
                    import we strongly recommend you delete the file at KEYSTORE_PASSWORD_PATH."
    )]
    pub password: Option<PathBuf>,
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(about = "Lists the public keys of all validators.")]
pub struct List {}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(
    about = "Recovers validator private keys given a BIP-39 mnemonic phrase. \
            If you did not specify a `--first-index` or count `--count`, by default this will \
            only recover the keys associated with the validator at index 0 for an HD wallet \
            in accordance with the EIP-2333 spec."
)]
pub struct Recover {
    #[clap(
        long,
        value_name = "FIRST_INDEX",
        help = "The first of consecutive key indexes you wish to recover.",
        default_value_t = 0
    )]
    pub first_index: u32,
    #[clap(
        long,
        value_name = "COUNT",
        help = "The number of validator keys you wish to recover. Counted consecutively from the provided `--first_index`.",
        default_value_t = 1
    )]
    pub count: u32,
    #[clap(
        long,
        value_name = "MNEMONIC_PATH",
        help = "If present, the mnemonic will be read in from this file."
    )]
    pub mnemonic: Option<PathBuf>,
    #[clap(
        long,
        value_name = "SECRETS_DIR",
        help = "The path where the validator keystore passwords will be stored. \
                    Defaults to ~/.lighthouse/{network}/secrets"
    )]
    pub secrets_dir: Option<PathBuf>,
    #[clap(
        long,
        help = "If present, the withdrawal keystore will be stored alongside the voting \
                    keypair. It is generally recommended to *not* store the withdrawal key and \
                    instead generate them from the wallet seed when required."
    )]
    pub store_withdraw: bool,
    #[clap(                hide = cfg!(windows),
    long,
    help = "If present, read all user inputs from stdin instead of tty.",)]
    pub stdin_inputs: bool,
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(about = "Import or export slashing protection data to or from another client")]
#[clap(rename_all = "snake_case")]
pub enum SlashingProtection {
    Import(SlashingProtectionImport),
    Export(SlashingProtectionExport),
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(about = "Import an interchange file")]
pub struct SlashingProtectionImport {
    #[clap(
        value_name = "FILE",
        help = "The slashing protection interchange file to import (.json)"
    )]
    pub import_file: PathBuf,
    #[clap(
    long,
    possible_values = &["false", "true"],
    help =
    "Deprecated: Lighthouse no longer requires minification on import \
                             because it always minifies",)]
    pub minify: Option<bool>,
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(about = "Export an interchange file")]
pub struct SlashingProtectionExport {
    #[clap(
        value_name = "FILE",
        help = "The filename to export the interchange file to"
    )]
    pub export_file: PathBuf,
    #[clap(
        long,
        value_name = "PUBKEYS",
        help = "List of public keys to export history for. Keys should be 0x-prefixed, \
                             comma-separated. All known keys will be exported if omitted"
    )]
    pub pubkeys: Option<String>,
    #[clap(                        long,
    default_value = "false",
    possible_values = &["false", "true"],
    help =
    "Minify the output file. This will make it smaller and faster to \
                             import, but not faster to generate.",)]
    pub minify: bool,
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(about = "Submits a VoluntaryExit to the beacon chain for a given validator keystore.")]
pub struct Exit {
    #[clap(
        long,
        value_name = "KEYSTORE_PATH",
        help = "The path to the EIP-2335 voting keystore for the validator",
    )]
    pub keystore: PathBuf,
    #[clap(
        long,
        value_name = "PASSWORD_FILE_PATH",
        help = "The path to the password file which unlocks the validator voting keystore"
    )]
    pub password_file: Option<PathBuf>,
    #[clap(                long,
    value_name = "NETWORK_ADDRESS",
    help = "Address to a beacon node HTTP API",
    default_value = DEFAULT_BEACON_NODE,)]
    pub beacon_server: String,
    #[clap(
        long,
        help = "Exits after publishing the voluntary exit without waiting for confirmation that the exit was included in the beacon chain"
    )]
    pub no_wait: bool,
    #[clap(
        long,
        help = "Exits without prompting for confirmation that you understand the implications of a voluntary exit. This should be used with caution"
    )]
    pub no_confirmation: bool,
    #[clap(                hide = cfg!(windows),
    long,
    help = "If present, read all user inputs from stdin instead of tty.",)]
    pub stdin_inputs: bool,
}
