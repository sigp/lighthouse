pub use clap::Parser;
use eth2::SensitiveUrl;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use types::Address;

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(about = "Provides commands for managing Eth2 validators.")]
pub struct ValidatorManager {
    #[clap(
        long,
        value_name = "VALIDATOR_DIRECTORY",
        help = "The path to search for validator directories. \
                    Defaults to ~/.lighthouse/{network}/validators",
        conflicts_with = "datadir"
    )]
    pub validator_dir: Option<PathBuf>,
    #[clap(subcommand)]
    pub subcommand: ValidatorManagerSubcommand,
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(rename_all = "kebab-case")]
pub enum ValidatorManagerSubcommand {
    Create(Create),
    Import(Import),
    Move(Move),
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(
    about = "Creates new validators from BIP-39 mnemonic. A JSON file will be created which \
    contains all the validator keystores and other validator data. This file can then \
    be imported to a validator client using the \"import-validators\" command. \
    Another, optional JSON file is created which contains a list of validator \
    deposits in the same format as the \"ethereum/staking-deposit-cli\" tool."
)]
pub struct Create {
    #[clap(
        long,
        value_name = "DIRECTORY",
        help = "The path to a directory where the validator and (optionally) deposits \
                files will be created. The directory will be created if it does not exist."
    )]
    pub output_path: PathBuf,

    #[clap(
        long,
        value_name = "DEPOSIT_GWEI",
        conflicts_with = "disable_deposits",
        help = "The GWEI value of the deposit amount. Defaults to the minimum amount \
                required for an active validator (MAX_EFFECTIVE_BALANCE)."
    )]
    pub deposit_gwei: Option<u64>,

    #[clap(
        long,
        value_name = "FIRST_INDEX",
        default_value_t = 0,
        help = "The first of consecutive key indexes you wish to create."
    )]
    pub first_index: u32,

    #[clap(
        long,
        value_name = "VALIDATOR_COUNT",
        conflicts_with = "at_most",
        help = "The number of validators to create, regardless of how many already exist."
    )]
    pub count: u32,

    #[clap(
        long,
        value_name = "MNEMONIC_PATH",
        help = "If present, the mnemonic will be read in from this file."
    )]
    pub mnemonic_path: Option<PathBuf>,

    #[clap(
        long,
        hide = cfg!(windows),
        help = "If present, read all user inputs from stdin instead of tty.",
    )]
    pub stdin_inputs: bool,

    #[clap(
        long,
        help = "When provided don't generate the deposits JSON file that is \
                commonly used for submitting validator deposits via a web UI. \
                Using this flag will save several seconds per validator if the \
                user has an alternate strategy for submitting deposits."
    )]
    pub disable_deposits: bool,

    #[clap(
        long,
        help = "If present, the user will be prompted to enter the voting keystore \
                password that will be used to encrypt the voting keystores. If this \
                flag is not provided, a random password will be used. It is not \
                necessary to keep backups of voting keystore passwords if the \
                mnemonic is safely backed up."
    )]
    pub specify_voting_keystore_password: bool,

    #[clap(
        long,
        value_name = "ETH1_ADDRESS",
        conflicts_with = "disable_deposits",
        help = "If this field is set, the given eth1 address will be used to create the \
                withdrawal credentials. Otherwise, it will generate withdrawal credentials \
                with the mnemonic-derived withdrawal public key in EIP-2334 format."
    )]
    pub eth1_withdrawal_address: Option<Address>,

    #[clap(
        long,
        value_name = "UINT64",
        help = "All created validators will use this gas limit. It is recommended \
                to leave this as the default valcue by not specifying this flag."
    )]
    pub gas_limit: Option<u64>,

    #[clap(
        long,
        value_name = "ETH1_ADDRESS",
        help = "All created validators will use this value for the suggested \
                fee recipient. Omit this flag to use the default value from the VC."
    )]
    pub suggested_fee_recipient: Option<Address>,

    // TODO this accepts a value
    #[clap(
        long,
        help = "When provided, all created validators will attempt to create \
                blocks via builder rather than the local EL."
    )]
    pub builder_proposals: bool,

    #[clap(
        long,
        value_name = "HTTP_ADDRESS",
        help = "A HTTP(S) address of a beacon node using the beacon-API. \
                If this value is provided, an error will be raised if any validator \
                key here is already known as a validator by that beacon node. This helps \
                prevent the same validator being created twice and therefore slashable \
                conditions."
    )]
    pub beacon_node: Option<String>,

    #[clap(
        long,
        help = "If present, allows BLS withdrawal credentials rather than an execution \
                address. This is not recommended."
    )]
    pub force_bls_withdrawal_credentials: bool,

    #[clap(
        long,
        value_name = "UINT64",
        help = "Defines the boost factor, \
                a percentage multiplier to apply to the builder's payload value \
                when choosing between a builder payload header and payload from \
                the local execution node."
    )]
    pub builder_boost_factor: Option<u64>,

    #[clap(
        long,
        help = "If this flag is set, Lighthouse will always prefer blocks \
                constructed by builders, regardless of payload value."
    )]
    pub prefer_builder_proposals: Option<bool>,
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(
    about = "Uploads validators to a validator client using the HTTP API. The validators \
            are defined in a JSON file which can be generated using the \"create-validators\" \
            command."
)]
pub struct Import {
    #[clap(
        long,
        value_name = "PATH_TO_JSON_FILE",
        help = "The path to a JSON file containing a list of validators to be \
                imported to the validator client. This file is usually named \
                \"validators.json\"."
    )]
    pub validators_file: PathBuf,

    #[clap(
        long,
        value_name = "PATH_TO_JSON_FILE",
        default_value_t = String::from("http://localhost:5062"),
        requires = "vc_token",
        help =  "A HTTP(S) address of a validator client using the keymanager-API. \
                If this value is not supplied then a 'dry run' will be conducted where \
                no changes are made to the validator client.",
    )]
    pub vc_url: String,

    #[clap(
        long,
        value_name = "PATH",
        help = "The file containing a token required by the validator client."
    )]
    pub vc_token: PathBuf,

    #[clap(
        long,
        help = "If present, ignore any validators which already exist on the VC. \
                Without this flag, the process will terminate without making any changes. \
                This flag should be used with caution, whilst it does not directly cause \
                slashable conditions, it might be an indicator that something is amiss. \
                Users should also be careful to avoid submitting duplicate deposits for \
                validators that already exist on the VC."
    )]
    pub ignore_duplicates: bool,
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(
    about = "Uploads validators to a validator client using the HTTP API. The validators \
            are defined in a JSON file which can be generated using the \"create-validators\" \
            command. This command only supports validators signing via a keystore on the local \
            file system (i.e., not Web3Signer validators)."
)]
pub struct Move {
    #[clap(
        long,
        value_name = "HTTP_ADDRESS",
        requires = "src_vc_token",
        help = "A HTTP(S) address of a validator client using the keymanager-API. \
                This validator client is the \"source\" and contains the validators \
                that are to be moved."
    )]
    pub src_vc_url: String,

    #[clap(
        long,
        value_name = "PATH",
        help = "The file containing a token required by the source validator client."
    )]
    pub src_vc_token: PathBuf,

    #[clap(
        long,
        value_name = "HTTP_ADDRESS",
        requires = "dest_vc_token",
        help = "A HTTP(S) address of a validator client using the keymanager-API. \
                This validator client is the \"destination\" and will have new validators \
                added as they are removed from the \"source\" validator client."
    )]
    pub dest_vc_url: String,

    #[clap(
        long,
        value_name = "PATH",
        help = "The file containing a token required by the destination validator client."
    )]
    pub dest_vc_token: PathBuf,

    #[clap(
        long,
        value_delimiter = ',',
        value_name = "STRING",
        help = "The validators to be moved. Either a list of 0x-prefixed \
                validator pubkeys or the keyword \"all\"."
    )]
    pub validators: Option<Vec<String>>,

    #[clap(
        long,
        value_name = "VALIDATOR_COUNT",
        conflicts_with = "validators",
        help = "The number of validators to move."
    )]
    pub count: Option<usize>,

    #[clap(
        long,
        value_name = "UINT64",
        help = "All created validators will use this gas limit. It is recommended \
                to leave this as the default value by not specifying this flag."
    )]
    pub gas_limit: Option<u64>,

    #[clap(
        long,
        value_name = "ETH1_ADDRESS",
        help = "All created validators will use this value for the suggested \
                fee recipient. Omit this flag to use the default value from the VC."
    )]
    pub suggested_fee_recipient: Option<Address>,

    // TODO this accepts a value
    #[clap(
        long,
        help = "When provided, all created validators will attempt to create \
                blocks via builder rather than the local EL."
    )]
    pub builder_proposals: Option<bool>,

    #[clap(
        long,
        hide = cfg!(windows),
        help = "If present, read all user inputs from stdin instead of tty.",
    )]
    pub stdin_inputs: bool,

    #[clap(
        long,
        value_name = "UINT64",
        help = "Defines the boost factor, \
                a percentage multiplier to apply to the builder's payload value \
                when choosing between a builder payload header and payload from \
                the local execution node."
    )]
    pub builder_boost_factor: Option<u64>,

    #[clap(
        long,
        help = "If this flag is set, Lighthouse will always prefer blocks \
                constructed by builders, regardless of payload value."
    )]
    pub prefer_builder_proposals: Option<bool>,
}
