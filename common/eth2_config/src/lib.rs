//! This crate primarily exists to serve the `common/eth2_network_configs` crate, by providing the
//! canonical list of built-in-networks and some tooling to help include those configurations in the
//! `lighthouse` binary.
//!
//! It also provides some additional structs which are useful to other components of `lighthouse`
//! (e.g., `Eth2Config`).

use std::{env, fs::File};
use types::{ChainSpec, EthSpecId};
use std::io::{self, BufReader, Cursor, Read, Write};
use std::path::PathBuf;
use tokio::runtime;
use tokio::task;
pub use paste::paste;

// A macro is used to define this constant so it can be used with `include_bytes!`.
#[macro_export]
macro_rules! predefined_networks_dir {
    () => {
        "built_in_network_configs"
    };
}

pub const PREDEFINED_NETWORKS_DIR: &str = predefined_networks_dir!();
pub const GENESIS_FILE_NAME: &str = "genesis.ssz";
pub const GENESIS_SNAPPY_ZIP_FILE_NAME: &str = "genesis.snappy.zip";
pub const GENESIS_SNAPPY_FILE_NAME: &str = "genesis.snappy";
pub const GENESIS_ZIP_FILE_NAME: &str = "genesis.ssz.zip";

/// The core configuration of a Lighthouse beacon node.
#[derive(Debug, Clone)]
pub struct Eth2Config {
    pub eth_spec_id: EthSpecId,
    pub spec: ChainSpec,
}

impl Default for Eth2Config {
    fn default() -> Self {
        Self {
            eth_spec_id: EthSpecId::Minimal,
            spec: ChainSpec::minimal(),
        }
    }
}

impl Eth2Config {
    pub fn mainnet() -> Self {
        Self {
            eth_spec_id: EthSpecId::Mainnet,
            spec: ChainSpec::mainnet(),
        }
    }

    pub fn minimal() -> Self {
        Self {
            eth_spec_id: EthSpecId::Minimal,
            spec: ChainSpec::minimal(),
        }
    }

    pub fn gnosis() -> Self {
        Self {
            eth_spec_id: EthSpecId::Gnosis,
            spec: ChainSpec::gnosis(),
        }
    }
}

/// A directory that can be built by downloading files via HTTP.
///
/// Used by the `eth2_network_config` crate to initialize the network directories during build and
/// access them at runtime.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Eth2NetArchiveAndDirectory<'a> {
    pub name: &'a str,
    pub config_dir: &'a str,
    pub remote_url: &'a str,
    pub genesis_is_known: bool,
}

impl<'a> Eth2NetArchiveAndDirectory<'a> {

    /// The directory that should be used to store files downloaded for this net.
    pub fn dir(&self) -> PathBuf {
        env::var("CARGO_MANIFEST_DIR")
            .expect("should know manifest dir")
            .parse::<PathBuf>()
            .expect("should parse manifest dir as path")
            .join(PREDEFINED_NETWORKS_DIR)
            .join(self.config_dir)
    }

    pub fn genesis_state_archive(&self) -> PathBuf {
        self.dir().join(GENESIS_ZIP_FILE_NAME)
    }

    /// Uncompress the network configs archive into a network configs folder.
    fn uncompress_state(network: &Eth2NetArchiveAndDirectory<'static>) -> Result<(), String> {
        let genesis_ssz_path = network.dir().join(GENESIS_FILE_NAME);
        let genesis_snappy_ssz_path = network.dir().join(GENESIS_SNAPPY_FILE_NAME);

        // Take care to not overwrite the genesis.ssz if it already exists, as that causes
        // spurious rebuilds.
        if genesis_ssz_path.exists() {
            return Ok(());
        }

        if network.genesis_is_known {
            // fetch snappy compressed genesis from remote url
            if !genesis_snappy_ssz_path.exists() {
                let rt = runtime::Runtime::new()
                    .map_err(|e| format!("Error with blocking tasks: {}", e))?;

                rt.block_on(Eth2NetArchiveAndDirectory::fetch_genesis_state_wrapper(
                    network .remote_url,
                    genesis_snappy_ssz_path.clone(),
                ))?;
            }

            let snappy_compressed_file =
                File::open(genesis_snappy_ssz_path.clone()).map_err(|e| {
                    format!(
                        "Failed to open zip file {}: {}",
                        GENESIS_SNAPPY_ZIP_FILE_NAME, e
                    )
                })?;

                Eth2NetArchiveAndDirectory::snappy_decode_genesis_file(snappy_compressed_file, genesis_ssz_path)?;
        } else {
            // Create empty genesis.ssz if genesis is unknown
            File::create(genesis_ssz_path)
                .map_err(|e| format!("Failed to create {}: {}", GENESIS_FILE_NAME, e))?;
        }

        Ok(())
    }

    async fn fetch_compressed_genesis_state(url: &str, save_path: PathBuf) -> Result<File, String> {
        let response = reqwest::get(url)
            .await
            .map_err(|e| format!("Error fetching file from remote url: {}", e))?;

        if response.status().is_success() {
            let mut dest = File::create(save_path)
                .map_err(|e| format!("Error creating file from remote url: {}", e))?;

            let mut content = Cursor::new(
                response
                    .bytes()
                    .await
                    .map_err(|e| format!("Failed to fetch bytes from request {}", e))?,
            );
            io::copy(&mut content, &mut dest).map_err(|e| format!("Error writing file {}", e))?;

            return Ok(dest);
        }
        Err("Could not find file from remote url".to_string())
    }

    async fn fetch_genesis_state_wrapper(
        url: &'static str,
        save_path: PathBuf,
    ) -> Result<File, String> {
        let join_handle = task::spawn_blocking(|| {
            let inner_runtime = runtime::Runtime::new().unwrap();
            inner_runtime.block_on(Eth2NetArchiveAndDirectory::fetch_compressed_genesis_state(url, save_path))
        });

        let result = join_handle
            .await
            .map_err(|e| format!("join handle error: {}", e))??;

        Ok(result)
    }

    fn snappy_decode_genesis_file(
        source_file: File,
        target_filename: PathBuf,
    ) -> Result<File, String> {
        let reader = BufReader::new(source_file);

        let mut decoder = snap::read::FrameDecoder::new(reader);

        let mut buffer = Vec::new();
        decoder
            .read_to_end(&mut buffer)
            .map_err(|e| format!("failed to decode: {}", e))?;

        let mut output_file = File::create(target_filename).unwrap();
        output_file
            .write_all(&buffer)
            .map_err(|e| format!("Error writing buffer: {}", e))?;

        Ok(output_file)
    }
}

/// Indicates that the `genesis.ssz.zip` file is present on the filesystem. This means that the
/// deposit ceremony has concluded and the final genesis `BeaconState` is known.
const GENESIS_STATE_IS_KNOWN: bool = true;

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct HardcodedNet {
    pub name: &'static str,
    pub config_dir: &'static str,
    pub genesis_is_known: bool,
    pub config: &'static [u8],
    pub deploy_block: &'static [u8],
    pub boot_enr: &'static [u8],
    pub genesis_state_bytes: &'static [u8],
}

/// Defines an `Eth2NetArchiveAndDirectory` for some network.
///
/// It also defines a `include_<title>_file!` macro which provides a wrapper around
/// `std::include_bytes`, allowing the inclusion of bytes from the specific testnet directory.
macro_rules! define_archive {
    ($name_ident: ident, $config_dir: tt, $remote_url: tt, $genesis_is_known: ident) => {
        paste! {
            #[macro_use]
            pub mod $name_ident {
                use super::*;

                pub const ETH2_NET_DIR: Eth2NetArchiveAndDirectory = Eth2NetArchiveAndDirectory {
                    name: stringify!($name_ident),
                    config_dir: $config_dir,
                    remote_url: $remote_url,
                    genesis_is_known: $genesis_is_known,
                };

                /// A wrapper around `std::include_bytes` which includes a file from a specific network
                /// directory. Used by upstream crates to import files at compile time.
                #[macro_export]
                macro_rules! [<include_ $name_ident _file>] {
                    ($this_crate: ident, $base_dir: tt, $filename: tt) => {
                        include_bytes!(concat!(
                            $base_dir,
                            "/",
                            $this_crate::predefined_networks_dir!(),
                            "/",
                            $config_dir,
                            "/",
                            $filename
                        ))
                    };
                }
            }
        }
    };
}

/// Creates a `HardcodedNet` definition for some network.
#[macro_export]
macro_rules! define_net {
    ($this_crate: ident, $mod: ident, $include_file: tt) => {{
        use $this_crate::$mod::ETH2_NET_DIR;

        $this_crate::HardcodedNet {
            name: ETH2_NET_DIR.name,
            config_dir: ETH2_NET_DIR.config_dir,
            genesis_is_known: ETH2_NET_DIR.genesis_is_known,
            config: $this_crate::$include_file!($this_crate, "../", "config.yaml"),
            deploy_block: $this_crate::$include_file!($this_crate, "../", "deploy_block.txt"),
            boot_enr: $this_crate::$include_file!($this_crate, "../", "boot_enr.yaml"),
            genesis_state_bytes: $this_crate::$include_file!($this_crate, "../", "genesis.ssz"),
        }
    }};
}

/// Calls `define_net` on a list of networks, and then defines two more lists:
///
/// - `HARDCODED_NETS`: a list of all the networks defined by this macro.
/// - `HARDCODED_NET_NAMES`: a list of the *names* of the networks defined by this macro.
#[macro_export]
macro_rules! define_nets {
    ($this_crate: ident, $($name_ident: ident,)+) => {
        $this_crate::paste! {
            $(
            const [<$name_ident:upper>]: $this_crate::HardcodedNet = $this_crate::define_net!($this_crate, $name_ident, [<include_ $name_ident _file>]);
            )+
            const HARDCODED_NETS: &[$this_crate::HardcodedNet] = &[$([<$name_ident:upper>],)+];
            pub const HARDCODED_NET_NAMES: &[&'static str] = &[$(stringify!($name_ident),)+];
        }
    };
}

/// The canonical macro for defining built-in network configurations.
///
/// This macro will provide:
///
/// - An `Eth2NetArchiveAndDirectory` for each network.
/// - `ETH2_NET_DIRS`: a list of all the above `Eth2NetArchiveAndDirectory`.
/// - The `instantiate_hardcoded_nets` macro (see its documentation).
///
/// ## Design Justification
///
/// Ultimately, this macro serves as a single list of all the networks. The reason it is structured
/// in such a complex web-of-macros way is because two requirements of built-in (hard-coded) networks:
///
/// 1. We must use `std::include_bytes!` to "bake" arbitrary bytes (genesis states, etc) into the binary.
/// 2. We must use a `build.rs` script to decompress the genesis state from a zip file, before we
///    can include those bytes.
///
/// Because of these two constraints, we must first define all of the networks and the paths to
/// their files in this crate. Then, we must use another crate (`eth2_network_configs`) to run a
/// `build.rs` which will unzip the genesis states. Then, that `eth2_network_configs` crate can
/// perform the final step of using `std::include_bytes` to bake the files (bytes) into the binary.
macro_rules! define_hardcoded_nets {
    ($(($name_ident: ident, $config_dir: tt, $remote_url: tt, $genesis_is_known: ident)),+) => {
        $(
        define_archive!($name_ident, $config_dir, $remote_url, $genesis_is_known);
        )+

        pub const ETH2_NET_DIRS: &[Eth2NetArchiveAndDirectory<'static>] = &[$($name_ident::ETH2_NET_DIR,)+];

        /// This macro is designed to be called by an external crate. When called, it will
        /// define in that external crate:
        ///
        /// - A `HardcodedNet` for each network.
        /// - `HARDCODED_NETS`: a list of all the above `HardcodedNet`.
        /// - `HARDCODED_NET_NAMES`: a list of all the names of the above `HardcodedNet` (as `&str`).
        #[macro_export]
        macro_rules! instantiate_hardcoded_nets {
            ($this_crate: ident) => {
                $this_crate::define_nets!($this_crate, $($name_ident,)+);
            }
        }
    };
}

// Add a new "built-in" network by adding it to the list below.
//
// The last entry must not end with a comma, otherwise compilation will fail.
//
// This is the canonical place for defining the built-in network configurations that are present in
// the `common/eth2_network_config/built_in_network_configs` directory.
//
// Each net is defined as a three-tuple:
//
// 0. The name of the testnet as an "ident" (i.e. something that can be a Rust variable name).
// 1. The human-friendly name of the testnet (i.e. usually with "-" instead of "_").
// 2. A bool indicating if the genesis state is known and present as a `genesis.ssz.zip`.
//
// The directory containing the testnet files should match the human-friendly name (element 1).
define_hardcoded_nets!(
    (
        // Network name (must be unique among all networks).
        mainnet,
        // The name of the directory in the `eth2_network_config/built_in_network_configs`
        // directory where the configuration files are located for this network.
        "mainnet",
        // The remote url that points to this networks genesis state file
        "https://raw.githubusercontent.com/eserilev/eth2_network_genesis/main/mainnet/genesis.snappy",
        // Set to `true` if the genesis state can be found in the `built_in_network_configs`
        // directory.
        GENESIS_STATE_IS_KNOWN
    ),
    (
        // Network name (must be unique among all networks).
        prater,
        // The name of the directory in the `eth2_network_config/built_in_network_configs`
        // directory where the configuration files are located for this network.
        "prater",
        // The remote url that points to this networks genesis state file
        "https://raw.githubusercontent.com/eserilev/eth2_network_genesis/main/prater/genesis.snappy",
        // Set to `true` if the genesis state can be found in the `built_in_network_configs`
        // directory.
        GENESIS_STATE_IS_KNOWN
    ),
    (
        // Network name (must be unique among all networks).
        goerli,
        // The name of the directory in the `eth2_network_config/built_in_network_configs`
        // directory where the configuration files are located for this network.
        //
        // The Goerli network is effectively an alias to Prater.
        "prater",
        // The remote url that points to this networks genesis state file
        "https://raw.githubusercontent.com/eserilev/eth2_network_genesis/main/goerli/genesis.snappy",
        // Set to `true` if the genesis state can be found in the `built_in_network_configs`
        // directory.
        GENESIS_STATE_IS_KNOWN
    ),
    
    (
        // Network name (must be unique among all networks).
        gnosis,
        // The name of the directory in the `eth2_network_config/built_in_network_configs`
        // directory where the configuration files are located for this network.
        "gnosis",
        // The remote url that points to this networks genesis state file
        "https://raw.githubusercontent.com/eserilev/eth2_network_genesis/main/gnosis/genesis.snappy",
        // Set to `true` if the genesis state can be found in the `built_in_network_configs`
        // directory.
        GENESIS_STATE_IS_KNOWN
    ), 
    (
        // Network name (must be unique among all networks).
        sepolia,
        // The name of the directory in the `eth2_network_config/built_in_network_configs`
        // directory where the configuration files are located for this network.
        "sepolia",
        // The remote url that points to this networks genesis state file
        "https://raw.githubusercontent.com/eserilev/eth2_network_genesis/main/sepolia/genesis.snappy",
        // Set to `true` if the genesis state can be found in the `built_in_network_configs`
        // directory.
        GENESIS_STATE_IS_KNOWN
    )
    /*
    (
        // Network name (must be unique among all networks).
        holesky,
        // The name of the directory in the `eth2_network_config/built_in_network_configs`
        // directory where the configuration files are located for this network.
        "holesky",
        // The remote url that points to this networks genesis state file
        "https://github.com/eth-clients/holesky/blob/main/consensus/genesis.ssz",
        // Set to `true` if the genesis state can be found in the `built_in_network_configs`
        // directory.
        GENESIS_STATE_IS_KNOWN
    ) */
);
