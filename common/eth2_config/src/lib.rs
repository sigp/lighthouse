use serde_derive::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;
use types::ChainSpec;

/// The core configuration of a Lighthouse beacon node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Eth2Config {
    pub spec_constants: String,
    pub spec: ChainSpec,
}

impl Default for Eth2Config {
    fn default() -> Self {
        Self {
            spec_constants: "minimal".to_string(),
            spec: ChainSpec::minimal(),
        }
    }
}

impl Eth2Config {
    pub fn mainnet() -> Self {
        Self {
            spec_constants: "mainnet".to_string(),
            spec: ChainSpec::mainnet(),
        }
    }

    pub fn minimal() -> Self {
        Self {
            spec_constants: "minimal".to_string(),
            spec: ChainSpec::minimal(),
        }
    }

    pub fn interop() -> Self {
        Self {
            spec_constants: "interop".to_string(),
            spec: ChainSpec::interop(),
        }
    }
}

/// A directory that can be built by downloading files via HTTP.
///
/// Used by the `eth2_testnet_config` crate to initialize testnet directories during build and
/// access them at runtime.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Eth2NetDirectory<'a> {
    pub name: &'a str,
    pub unique_id: &'a str,
    pub commit: &'a str,
    pub url_template: &'a str,
    pub genesis_is_known: bool,
}

impl<'a> Eth2NetDirectory<'a> {
    /// The directory that should be used to store files downloaded for this net.
    pub fn dir(&self) -> PathBuf {
        env::var("CARGO_MANIFEST_DIR")
            .expect("should know manifest dir")
            .parse::<PathBuf>()
            .expect("should parse manifest dir as path")
            .join(self.unique_id)
    }
}

#[macro_export]
macro_rules! unique_id {
    ($name: tt, $commit: tt, $genesis_is_known: tt) => {
        concat!("testnet_", $name, "_", $commit, "_", $genesis_is_known);
    };
}

macro_rules! define_net {
    ($title: ident, $macro_title: tt, $name: tt, $commit: tt, $url_template: tt, $genesis_is_known: tt) => {
        #[macro_use]
        pub mod $title {
            use super::*;

            pub const ETH2_NET_DIR: Eth2NetDirectory = Eth2NetDirectory {
                name: $name,
                unique_id: unique_id!($name, $commit, $genesis_is_known),
                commit: $commit,
                url_template: $url_template,
                genesis_is_known: $genesis_is_known,
            };

            // A wrapper around `std::include_bytes` which includes a file from a specific testnet
            // directory. Used by upstream crates to import files at compile time.
            #[macro_export]
            macro_rules! $macro_title {
                ($base_dir: tt, $filename: tt) => {
                    include_bytes!(concat!(
                        $base_dir,
                        unique_id!($name, $commit, $genesis_is_known),
                        "/",
                        $filename
                    ))
                };
            }
        }
    };
}

define_net!(
    altona,
    include_altona_file,
    "altona",
    "a94e00c1a03df851f960fcf44a79f2a6b1d29af1",
    "https://raw.githubusercontent.com/sigp/witti/{{ commit }}/altona/lighthouse/{{ file }}",
    true
);

define_net!(
    medalla,
    include_medalla_file,
    "medalla",
    "b21fef76ddf472c6cea62d5c98b678033a9b195a",
    "https://raw.githubusercontent.com/sigp/witti/{{ commit }}/medalla/{{ file }}",
    false
);

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
