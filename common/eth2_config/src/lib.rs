use serde_derive::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;
use types::{ChainSpec, EthSpecId};

// A macro is used to define this constant so it can be used with `include_bytes!`.
#[macro_export]
macro_rules! testnets_dir {
    () => {
        "built_in_testnet_configs"
    };
}

pub const TESTNETS_DIR: &str = testnets_dir!();
pub const GENESIS_FILE_NAME: &str = "genesis.ssz";
pub const GENESIS_ZIP_FILE_NAME: &str = "genesis.ssz.zip";

/// The core configuration of a Lighthouse beacon node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
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

    pub fn v012_legacy() -> Self {
        Self {
            eth_spec_id: EthSpecId::V012Legacy,
            spec: ChainSpec::v012_legacy(),
        }
    }
}

/// A directory that can be built by downloading files via HTTP.
///
/// Used by the `eth2_testnet_config` crate to initialize testnet directories during build and
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
            .join(TESTNETS_DIR)
            .join(self.unique_id)
    }

    pub fn genesis_state_archive(&self) -> PathBuf {
        self.dir().join(GENESIS_ZIP_FILE_NAME)
    }
}

macro_rules! define_net {
    ($title: ident, $macro_title: tt, $name: tt, $genesis_is_known: tt) => {
        #[macro_use]
        pub mod $title {
            use super::*;

            pub const ETH2_NET_DIR: Eth2NetArchiveAndDirectory = Eth2NetArchiveAndDirectory {
                name: $name,
                unique_id: $name,
                genesis_is_known: $genesis_is_known,
            };

            // A wrapper around `std::include_bytes` which includes a file from a specific testnet
            // directory. Used by upstream crates to import files at compile time.
            #[macro_export]
            macro_rules! $macro_title {
                ($base_dir: tt, $filename: tt) => {
                    include_bytes!(concat!(
                        $base_dir,
                        "/",
                        testnets_dir!(),
                        "/",
                        $name,
                        "/",
                        $filename
                    ))
                };
            }
        }
    };
}

define_net!(altona, include_altona_file, "altona", true);

define_net!(medalla, include_medalla_file, "medalla", true);

define_net!(spadina, include_spadina_file, "spadina", true);

define_net!(pyrmont, include_pyrmont_file, "pyrmont", true);

define_net!(mainnet, include_mainnet_file, "mainnet", false);

define_net!(toledo, include_toledo_file, "toledo", true);

#[cfg(test)]
mod tests {
    use super::*;
    use toml;

    #[test]
    fn serde_serialize() {
        let _ =
            toml::to_string(&Eth2Config::default()).expect("Should serde encode default config");
    }
}
