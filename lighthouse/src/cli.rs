use bls::Hash256;
pub use clap::{IntoApp, Parser};
use clap_utils::GlobalConfig;
use eth2_hashing::have_sha_extensions;
use eth2_network_config::{Eth2NetworkConfig, DEFAULT_HARDCODED_NETWORK, HARDCODED_NET_NAMES};
use lazy_static::lazy_static;
use lighthouse_version::VERSION;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use types::{Epoch, Uint256};

// These have to live at least as long as the `Lighthouse` app.
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
                     node, a validator client and utilities for managing validator accounts."
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
        help = "Enables environment logging giving access to sub-protocol logs such as discv5 and libp2p"
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
    value_name = "LEVEL",
    help = "The verbosity level used when emitting logs to the log file.",
    possible_values = &["info","debug","trace","warn","error","crit"],
    default_value = "debug",
    global = true
    )]
    pub logfile_debug_level: String,
    #[clap(
        long,
        value_name = "SIZE",
        help = "The maximum size  = in MB, each log file can grow to before rotating. If set \
                   to 0, background file logging is disabled.",
        default_value = "200",
        global = true
    )]
    pub logfile_max_size: u64,
    #[clap(
        long,
        value_name = "COUNT",
        help = "The maximum number of log files that will be stored. If set to 0, \
                   background file logging is disabled.",
        default_value = "5",
        global = true
    )]
    pub logfile_max_number: usize,
    #[clap(
        long,
        help = "If present, compress old log files. This can help reduce the space needed \
                   to store old logs.",
        global = true
    )]
    pub logfile_compress: bool,
    #[clap(
    long,
    value_name = "FORMAT",
    help = "Specifies the log format used when emitting logs to the terminal.",
    possible_values = &["JSON"],
    global = true
    )]
    pub log_format: Option<String>,
    #[clap(
    long,
    value_name = "LEVEL",
    help = "Specifies the verbosity level used when emitting logs to the terminal.",
    possible_values = &["info","debug","trace","warn","error","crit"],
    global = true,
    default_value = "info"
    )]
    pub debug_level: String,
    #[clap(
        long,
        short,
        value_name = "DIR",
        global = true,
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
                     existing database.",
        global = true
    )]
    pub testnet_dir: Option<PathBuf>,
    #[clap(
    long,
    value_name = "network",
    help = "Name of the Eth2 chain Lighthouse will sync and follow.",
    possible_values = HARDCODED_NET_NAMES,
    conflicts_with = "testnet_dir_flag",
    global = true
    )]
    pub network: Option<String>,
    #[clap(
        long,
        hide = true,
        help = "Dumps the config to a desired location. Used for testing only.",
        global = true
    )]
    pub dump_config: Option<PathBuf>,
    #[clap(
        long,
        hide = true,
        help = "Shuts down immediately after the Beacon Node or Validator has successfully launched. \
                Used for testing only, DO NOT USE IN PRODUCTION.",
        global = true
    )]
    pub immediate_shutdown: bool,
    #[clap(
        long,
        help = "If present, do not configure the system allocator. Providing this flag will \
                generally increase memory usage, it should only be provided when debugging \
                specific memory allocation issues.",
        global = true
    )]
    pub disable_malloc_tuning: bool,
    #[clap(
        long,
        value_name = "INTEGER",
        help = "Used to coordinate manual overrides to the TERMINAL_TOTAL_DIFFICULTY parameter. \
                      Accepts a 256-bit decimal integer  = not a hex value,. \
                      This flag should only be used if the user has a clear understanding that \
                      the broad Ethereum community has elected to override the terminal difficulty. \
                      Incorrect use of this flag will cause your node to experience a consensus
                      failure. Be extremely careful with this flag.",
        global = true
    )]
    pub terminal_total_difficulty_override: Option<Uint256>,
    #[clap(
        long,
        value_name = "TERMINAL_BLOCK_HASH",
        help = "Used to coordinate manual overrides to the TERMINAL_BLOCK_HASH parameter. \
                      This flag should only be used if the user has a clear understanding that \
                      the broad Ethereum community has elected to override the terminal PoW block. \
                      Incorrect use of this flag will cause your node to experience a consensus
                      failure. Be extremely careful with this flag.",
        requires = "terminal_block_hash_epoch_override",
        global = true
    )]
    pub terminal_block_hash_override: Option<Hash256>,
    #[clap(
        long,
        value_name = "EPOCH",
        help = "Used to coordinate manual overrides to the TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH \
                      parameter. This flag should only be used if the user has a clear understanding \
                      that the broad Ethereum community has elected to override the terminal PoW block. \
                      Incorrect use of this flag will cause your node to experience a consensus
                      failure. Be extremely careful with this flag.",
        requires = "terminal_block_hash_override",
        global = true
    )]
    pub terminal_block_hash_epoch_override: Option<Epoch>,
    #[clap(subcommand)]
    pub subcommand: LighthouseSubcommand,
}

pub const BAD_TESTNET_DIR_MESSAGE: &str = "The hard-coded testnet directory was invalid. \
                                        This happens when Lighthouse is migrating between spec versions \
                                        or when there is no default public network to connect to. \
                                        During these times you must specify a --testnet-dir.";

impl Lighthouse {
    /// Returns true if the provided command was to start a beacon node.
    pub fn is_beacon_node(&self) -> bool {
        matches!(&self.subcommand, LighthouseSubcommand::BeaconNode(_))
    }

    /// Try to parse the eth2 network config from the `network`, `testnet-dir` flags in that order.
    /// Returns the default hardcoded testnet if neither flags are set.
    pub fn get_eth2_network_config(&self) -> Result<Eth2NetworkConfig, String> {
        let optional_network_config = if let Some(network) = self.network.as_ref() {
            Eth2NetworkConfig::constant(network)?
        } else if let Some(testnet_dir) = self.testnet_dir.as_ref() {
            Eth2NetworkConfig::load(testnet_dir.clone())
                .map_err(|e| format!("Unable to open testnet dir at {:?}: {}", testnet_dir, e))
                .map(Some)?
        } else {
            // if neither is present, assume the default network
            Eth2NetworkConfig::constant(DEFAULT_HARDCODED_NETWORK)?
        };

        let mut eth2_network_config =
            optional_network_config.ok_or_else(|| BAD_TESTNET_DIR_MESSAGE.to_string())?;

        if let Some(terminal_total_difficulty) = self.terminal_total_difficulty_override {
            //TODO: do we need to accept deserializing from commas?
            eth2_network_config.config.terminal_total_difficulty = terminal_total_difficulty;
        }

        if let Some(hash) = self.terminal_block_hash_override {
            eth2_network_config.config.terminal_block_hash = hash;
        }

        if let Some(epoch) = self.terminal_block_hash_epoch_override {
            eth2_network_config
                .config
                .terminal_block_hash_activation_epoch = epoch;
        }

        Ok(eth2_network_config)
    }

    pub fn get_global_config(&self) -> GlobalConfig {
        GlobalConfig {
            config_file: self.config_file.clone(),
            spec: self.spec.clone(),
            logfile: self.logfile.clone(),
            logfile_debug_level: self.logfile_debug_level.clone(),
            logfile_max_size: self.logfile_max_size,
            logfile_max_number: self.logfile_max_number,
            logfile_compress: self.logfile_compress,
            log_format: self.log_format.clone(),
            debug_level: self.debug_level.clone(),
            datadir: self.datadir.clone(),
            testnet_dir: self.testnet_dir.clone(),
            network: self.network.clone(),
            dump_config: self.dump_config.clone(),
            immediate_shutdown: self.immediate_shutdown,
            disable_malloc_tuning: self.disable_malloc_tuning,
            terminal_total_difficulty_override: self.terminal_total_difficulty_override,
            terminal_block_hash_override: self.terminal_block_hash_override,
            terminal_block_hash_epoch_override: self.terminal_block_hash_epoch_override,
        }
    }
}

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
#[clap(rename_all = "snake_case")]
pub enum LighthouseSubcommand {
    BeaconNode(Box<beacon_node::BeaconNode>),
    ValidatorClient(validator_client::ValidatorClient),
    BootNode(boot_node::BootNode),
    #[clap(subcommand)]
    AccountManager(account_manager::AccountManager),
}
