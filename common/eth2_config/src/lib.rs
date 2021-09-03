//! This crate primarily exists to serve the `common/eth2_network_configs` crate, by providing the
//! canonical list of built-in-networks and some tooling to help include those configurations in the
//! `lighthouse` binary.
//!
//! It also provides some additional structs which are useful to other components of `lighthouse`
//! (e.g., `Eth2Config`).

use std::env;
use std::path::PathBuf;
use types::{ChainSpec, EthSpecId};

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
}

/// A directory that can be built by downloading files via HTTP.
///
/// Used by the `eth2_network_config` crate to initialize the network directories during build and
/// access them at runtime.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Eth2NetArchiveAndDirectory<'a> {
    pub name: &'a str,
    pub unique_id: &'a str,
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
            .join(self.unique_id)
    }

    pub fn genesis_state_archive(&self) -> PathBuf {
        self.dir().join(GENESIS_ZIP_FILE_NAME)
    }
}

/// Indicates that the `genesis.ssz.zip` file is present on the filesystem. This means that the
/// deposit ceremony has concluded and the final genesis `BeaconState` is known.
const GENESIS_STATE_IS_KNOWN: bool = true;

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct HardcodedNet {
    pub name: &'static str,
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
    ($name_ident: ident, $name_str: tt, $genesis_is_known: ident) => {
        paste! {
            #[macro_use]
            pub mod $name_ident {
                use super::*;

                pub const ETH2_NET_DIR: Eth2NetArchiveAndDirectory = Eth2NetArchiveAndDirectory {
                    name: $name_str,
                    unique_id: $name_str,
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
                            $name_str,
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
    ($this_crate: ident, $($name_ident: ident, $name_str: tt,)+) => {
        $this_crate::paste! {
            $(
            const [<$name_ident:upper>]: $this_crate::HardcodedNet = $this_crate::define_net!($this_crate, $name_ident, [<include_ $name_ident _file>]);
            )+
            const HARDCODED_NETS: &[$this_crate::HardcodedNet] = &[$([<$name_ident:upper>],)+];
            pub const HARDCODED_NET_NAMES: &[&'static str] = &[$($name_str,)+];
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
    ($(($name_ident: ident, $name_str: tt, $genesis_is_known: ident)),+) => {
        $(
        define_archive!($name_ident, $name_str, $genesis_is_known);
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
                $this_crate::define_nets!($this_crate, $($name_ident, $name_str,)+);
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
    (mainnet, "mainnet", GENESIS_STATE_IS_KNOWN),
    (pyrmont, "pyrmont", GENESIS_STATE_IS_KNOWN),
    (prater, "prater", GENESIS_STATE_IS_KNOWN)
);
