//! A helper library for parsing values from `clap::ArgMatches`.

use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;
use clap_utils::GlobalConfig;
use eth2_network_config::{Eth2NetworkConfig, DEFAULT_HARDCODED_NETWORK};
use ethereum_hashing::have_sha_extensions;
use lazy_static::lazy_static;
use lighthouse_version::VERSION;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use types::ExecutionBlockHash;
use types::{Epoch, Hash256, Uint256};

pub const BAD_TESTNET_DIR_MESSAGE: &str = "The hard-coded testnet directory was invalid. \
                                        This happens when Lighthouse is migrating between spec versions \
                                        or when there is no default public network to connect to. \
                                        During these times you must specify a --testnet-dir.";

lazy_static! {
    pub static ref SHORT_VERSION: String = VERSION.replace("Lighthouse/", "");
    pub static ref LONG_VERSION: String = format!(
        "{}\n\
                    BLS library: {}\n\
                    SHA256 hardware acceleration: {}\n\
                    Specs: mainnet (true), minimal ({}), gnosis ({})",
        VERSION.replace("Lighthouse/", ""),
        bls_library_name(),
        have_sha_extensions(),
        cfg!(feature = "spec-minimal"),
        cfg!(feature = "gnosis"),
    );
}

fn bls_library_name() -> &'static str {
    if cfg!(feature = "portable") {
        "blst-portable"
    } else if cfg!(feature = "modern") {
        "blst-modern"
    } else if cfg!(feature = "milagro") {
        "milagro"
    } else {
        "blst"
    }
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(
    name = "Lighthouse",
    version = SHORT_VERSION.as_str(),
    long_version = LONG_VERSION.as_str(),
    author = "Sigma Prime <contact@sigmaprime.io>",
    about = "Ethereum 2.0 client by Sigma Prime. Provides a full-featured beacon \
                        node, a validator client and utilities for managing validator accounts.",
)]
pub struct Lighthouse {
    #[clap(
        long,
        help = "The filepath to a YAML or TOML file with flag values. The filename must \
                    end in `.toml`, `.yml`, or `.yaml`. To override any options in \
                    the config file, specify the same option in the command line.",
        global = true
    )]
    pub config_file: Option<PathBuf>,

    #[clap(
        long,
        short,
        value_name = "DEPRECATED",
        help = "This flag is deprecated, it will be disallowed in a future release. This \
                        value is now derived from the --network or --testnet-dir flags.",
        global = true
    )]
    pub spec: Option<String>,

    #[clap(
        short = 'l',
        help = "DEPRECATED Enables environment logging giving access to sub-protocol logs such as discv5 and libp2p."
    )]
    pub env_log: bool,

    #[clap(
        long,
        value_name = "FILE",
        help = "File path where the log file will be stored. Once it grows to the \
                value specified in `--logfile-max-size` a new log file is generated where \
                future logs are stored. \
                Once the number of log files exceeds the value specified in \
                `--logfile-max-number` the oldest log file will be overwritten.",
        global = true
    )]
    pub logfile: Option<PathBuf>,

    #[clap(
        long,
        value_enum,
        default_value_t = LogLevel::Debug,
        help = "The verbosity level used when emitting logs to the log file.",
    )]
    pub logfile_debug_level: LogLevel,

    #[clap(
        long,
        value_name = "SIZE",
        help = "The maximum size  = in MB, each log file can grow to before rotating. If set \
                to 0, background file logging is disabled.",
        default_value_t = 200,
        global = true
    )]
    pub logfile_max_size: u64,

    // TODO the only optional value here is JSON
    #[clap(
        long,
        value_name = "FORMAT",
        default_value_t = String::from("JSON"),
        help = "Specifies the log format used when emitting logs to the terminal.",
    )]
    pub log_format: String,

    #[clap(
        long,
        value_name = "COUNT",
        help = "The maximum number of log files that will be stored. If set to 0, \
                background file logging is disabled.",
        default_value_t = 5,
        global = true
    )]
    pub logfile_max_number: usize,

    #[clap(
        long,
        help = "If present, compress old log files. This can help reduce the space needed \
                to store old logs."
    )]
    pub logfile_compress: bool,

    #[clap(
        long,
        value_enum,
        default_value_t = LogFormat::Default,
        help = "Specifies the log format used when emitting logs to the terminal.",
    )]
    pub logfile_format: LogFormat,

    #[clap(
        long,
        help = "If present, log files will be generated as world-readable meaning they can be read by \
                any user on the machine. Note that logs can often contain sensitive information \
                about your validator and so this flag should be used with caution. For Windows users, \
                the log file permissions will be inherited from the parent folder."
    )]
    pub logfile_no_restricted_perms: bool,

    #[clap(
        long,
        alias = "log-colour",
        help = "Force outputting colors when emitting logs to the terminal."
    )]
    pub log_color: bool,

    #[clap(
        long,
        help = "If present, do not include timestamps in logging output."
    )]
    pub disable_log_timestamp: bool,

    #[clap(
        long,
        value_enum,
        default_value_t = LogLevel::Info,
        help = "Specifies the verbosity level used when emitting logs to the terminal.",
    )]
    pub debug_level: LogLevel,

    #[clap(
        long,
        short,
        value_name = "DIR",
        help = "Used to specify a custom root data directory for lighthouse keys and databases. \
                Defaults to $HOME/.lighthouse/{network} where network is the value of the `network` flag \
                Note: Users should specify separate custom datadirs for different networks."
    )]
    pub datadir: Option<PathBuf>,

    #[clap(
        long,
        short,
        value_name = "DIR",
        help = "Path to directory containing eth2_testnet specs. Defaults to \
                a hard-coded Lighthouse testnet. Only effective if there is no \
                existing database."
    )]
    pub testnet_dir: Option<PathBuf>,

    #[clap(
        long,
        value_name = "network",
        conflicts_with = "testnet_dir",
        help = "Name of the Eth2 chain Lighthouse will sync and follow."
    )]
    pub network: Option<NetworkName>,

    #[clap(
        long,
        hide = true,
        help = "Dumps the config to a desired location. Used for testing only."
    )]
    pub dump_config: Option<PathBuf>,

    #[clap(
        long,
        hide = true,
        help = "Dumps the chain config to a desired location. Used for testing only."
    )]
    pub dump_chain_config: Option<PathBuf>,

    #[clap(
        long,
        hide = true,
        help = "Shuts down immediately after the Beacon Node or Validator has successfully launched. \
                Used for testing only, DO NOT USE IN PRODUCTION."
    )]
    pub immediate_shutdown: bool,

    #[clap(
        long,
        help = "If present, do not configure the system allocator. Providing this flag will \
                generally increase memory usage, it should only be provided when debugging \
                specific memory allocation issues."
    )]
    pub disable_malloc_tuning: bool,

    #[clap(
        long,
        value_name = "INTEGER",
        help = "Used to coordinate manual overrides to the TERMINAL_TOTAL_DIFFICULTY parameter. \
                Accepts a 256-bit decimal integer  = not a hex value,. \
                This flag should only be used if the user has a clear understanding that \
                the broad Ethereum community has elected to override the terminal difficulty. \
                Incorrect use of this flag will cause your node to experience a consensus \
                failure. Be extremely careful with this flag."
    )]
    // Parse this as a string so we can accept numbers with commas.
    pub terminal_total_difficulty_override: Option<String>,

    #[clap(
        long,
        value_name = "TERMINAL_BLOCK_HASH",
        help = "Used to coordinate manual overrides to the TERMINAL_BLOCK_HASH parameter. \
                This flag should only be used if the user has a clear understanding that \
                the broad Ethereum community has elected to override the terminal PoW block. \
                Incorrect use of this flag will cause your node to experience a consensus \
                failure. Be extremely careful with this flag.",
        requires = "terminal-block-hash-epoch-override"
    )]
    pub terminal_block_hash_override: Option<Hash256>,

    #[clap(
        long,
        value_name = "EPOCH",
        help = "Used to coordinate manual overrides to the TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH \
                parameter. This flag should only be used if the user has a clear understanding \
                that the broad Ethereum community has elected to override the terminal PoW block. \
                Incorrect use of this flag will cause your node to experience a consensus \
                failure. Be extremely careful with this flag.",
        requires = "terminal-block-hash-override",
        global = true
    )]
    pub terminal_block_hash_epoch_override: Option<Epoch>,

    #[clap(
        long,
        value_name = "INTEGER",
        help = "Used to coordinate manual overrides of the SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY \
                parameter. This flag should only be used if the user has a clear understanding \
                that the broad Ethereum community has elected to override this parameter in the event \
                of an attack at the PoS transition block. Incorrect use of this flag can cause your \
                node to possibly accept an invalid chain or sync more slowly. Be extremely careful with \
                this flag."
    )]
    pub safe_slots_to_import_optimistically: Option<u64>,

    #[clap(
        long,
        value_name = "URL",
        help = "A URL of a beacon-API compatible server from which to download the genesis state. \
                Checkpoint sync server URLs can generally be used with this flag. \
                If not supplied, a default URL or the --checkpoint-sync-url may be used. \
                If the genesis state is already included in this binary then this value will be ignored."
    )]
    pub genesis_state_url: Option<String>,

    #[clap(
        long,
        value_name = "SECONDS",
        default_value_t = 180,
        help = "genesis-state-url-timeout."
    )]
    pub genesis_state_url_timeout: u64,

    #[command(subcommand)]
    pub subcommand: LighthouseSubcommand,
}

#[derive(Clone, Deserialize, Serialize, Debug, Subcommand)]
pub enum LighthouseSubcommand {
    BeaconNode(Box<beacon_node::cli::BeaconNode>),
    ValidatorClient(validator_client::cli::ValidatorClient),
    BootNode(boot_node::cli::BootNode),
    AccountManager(account_manager::AccountManager),
    DatabaseManager(database_manager::cli::DatabaseManager),
    ValidatorManager(validator_manager::cli::ValidatorManager),
}

impl Lighthouse {
    pub fn get_global_config(&self) -> GlobalConfig {
        let network_name = if let Some(network) = self.network {
            network.to_str()
        } else {
            String::from(DEFAULT_HARDCODED_NETWORK)
        };

        GlobalConfig {
            config_file: self.config_file.clone(),
            spec: self.spec.clone(),
            logfile: self.logfile.clone(),
            logfile_debug_level: self.logfile_debug_level.to_str(),
            logfile_max_size: self.logfile_max_size,
            logfile_max_number: self.logfile_max_number,
            logfile_compress: self.logfile_compress,
            log_format: String::from("JSON"),
            debug_level: self.debug_level.to_str(),
            datadir: self.datadir.clone(),
            testnet_dir: self.testnet_dir.clone(),
            network: Some(network_name),
            dump_config: self.dump_config.clone(),
            immediate_shutdown: self.immediate_shutdown,
            disable_malloc_tuning: self.disable_malloc_tuning,
            terminal_total_difficulty_override: self.terminal_total_difficulty_override.clone(),
            terminal_block_hash_override: self.terminal_block_hash_override,
            terminal_block_hash_epoch_override: self.terminal_block_hash_epoch_override,
            dump_chain_config: self.dump_chain_config.clone(),
            genesis_state_url: self.genesis_state_url.clone(),
            genesis_state_url_timeout: self.genesis_state_url_timeout,
        }
    }

    /// Try to parse the eth2 network config from the `network`, `testnet-dir` flags in that order.
    /// Returns the default hardcoded testnet if neither flags are set.
    pub fn get_eth2_network_config(&self) -> Result<Eth2NetworkConfig, String> {
        let optional_network_config = if let Some(network) = self.network.as_ref() {
            load_hardcoded_network(&network.to_str())?
        } else if let Some(testnet_dir) = self.testnet_dir.as_ref() {
            load_testnet_dir(testnet_dir)?
        } else {
            // if neither is present, assume the default network
            Eth2NetworkConfig::constant(DEFAULT_HARDCODED_NETWORK)?
        };

        let mut eth2_network_config =
            optional_network_config.ok_or_else(|| BAD_TESTNET_DIR_MESSAGE.to_string())?;

        if let Some(string) = self.terminal_total_difficulty_override.clone() {
            let stripped = string.replace(',', "");
            let terminal_total_difficulty = Uint256::from_dec_str(&stripped).map_err(|e| {
                format!(
                    "Could not parse --terminal-total-difficulty-override as decimal value: {:?}",
                    e
                )
            })?;

            eth2_network_config.config.terminal_total_difficulty = terminal_total_difficulty;
        }

        if let Some(hash) = self.terminal_block_hash_override {
            eth2_network_config.config.terminal_block_hash = ExecutionBlockHash(hash);
        }

        if let Some(epoch) = self.terminal_block_hash_epoch_override {
            eth2_network_config
                .config
                .terminal_block_hash_activation_epoch = epoch;
        }

        if let Some(slots) = self.safe_slots_to_import_optimistically {
            eth2_network_config
                .config
                .safe_slots_to_import_optimistically = slots;
        }

        Ok(eth2_network_config)
    }
}

/// Attempts to load the testnet dir at the path, returning an error if
/// the path cannot be found or the testnet dir is invalid.
pub fn load_testnet_dir(path: &PathBuf) -> Result<Option<Eth2NetworkConfig>, String> {
    Eth2NetworkConfig::load(path.clone())
        .map_err(|e| format!("Unable to open testnet dir at {:?}: {}", path, e))
        .map(Some)
}

/// Attempts to load a hardcoded network config, returning an error if
/// the name is not a valid network name.
pub fn load_hardcoded_network(network_name: &str) -> Result<Option<Eth2NetworkConfig>, String> {
    Eth2NetworkConfig::constant(network_name)
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum LogLevel {
    Info,
    Debug,
    Trace,
    Warn,
    Error,
    Crit,
}

impl LogLevel {
    pub fn to_str(self) -> String {
        match self {
            LogLevel::Info => String::from("info"),
            LogLevel::Debug => String::from("debug"),
            LogLevel::Trace => String::from("trace"),
            LogLevel::Warn => String::from("warn"),
            LogLevel::Error => String::from("error"),
            LogLevel::Crit => String::from("crit"),
        }
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum LogFormat {
    Default,
    Json,
}

impl LogFormat {
    pub fn to_str(self) -> String {
        match self {
            LogFormat::Default => String::from("DEFAULT"),
            LogFormat::Json => String::from("JSON"),
        }
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum NetworkName {
    Mainnet,
    Prater,
    Goerli,
    Gnosis,
    Chiado,
    Sepolia,
    Holesky,
}

impl NetworkName {
    pub fn to_str(self) -> String {
        match self {
            NetworkName::Mainnet => String::from("mainnet"),
            NetworkName::Prater => String::from("prater"),
            NetworkName::Goerli => String::from("goerli"),
            NetworkName::Gnosis => String::from("gnosis"),
            NetworkName::Chiado => String::from("chiado"),
            NetworkName::Sepolia => String::from("sepolia"),
            NetworkName::Holesky => String::from("holesky"),
        }
    }
}
