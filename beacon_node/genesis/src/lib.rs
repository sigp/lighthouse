mod common;
mod eth1_genesis_service;
mod interop;

pub use eth1::Config as Eth1Config;
pub use eth1_genesis_service::Eth1GenesisService;
pub use interop::{interop_genesis_state, recent_genesis_time};
pub use types::test_utils::generate_deterministic_keypairs;

use environment::RuntimeContext;
use futures::{Future, IntoFuture};
use ssz::Decode;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use std::time::Duration;
use types::{BeaconState, ChainSpec, EthSpec};

const ETH1_GENESIS_UPDATE_INTERVAL_MILLIS: u64 = 500;

pub enum Eth2Genesis {
    Interop {
        validator_count: usize,
        genesis_time: u64,
    },
    DepositContract {
        config: Eth1Config,
    },
    SszFile {
        path: PathBuf,
    },
    RemoteNode {
        server: String,
        port: Option<u16>,
    },
}

impl Eth2Genesis {
    pub fn into_genesis_state<T: EthSpec>(
        self,
        context: RuntimeContext<T>,
        spec: &ChainSpec,
    ) -> Box<dyn Future<Item = BeaconState<T>, Error = String> + Send> {
        match self {
            Eth2Genesis::Interop {
                validator_count,
                genesis_time,
            } => {
                let keypairs = generate_deterministic_keypairs(validator_count);
                let result = interop_genesis_state(&keypairs, genesis_time, spec);

                Box::new(result.into_future())
            }
            Eth2Genesis::SszFile { path } => {
                let result = state_from_ssz_file(path);

                Box::new(result.into_future())
            }
            Eth2Genesis::DepositContract { config } => {
                let genesis_service = Eth1GenesisService::new(
                    Eth1Config {
                        block_cache_truncation: None,
                        ..config
                    },
                    context.log.clone(),
                );

                let future = genesis_service.wait_for_genesis_state(
                    Duration::from_millis(ETH1_GENESIS_UPDATE_INTERVAL_MILLIS),
                    context.eth2_config().spec.clone(),
                );

                Box::new(future)
            }
            // FIXME
            _ => panic!(),
        }
    }
}

/// Load a `BeaconState` from the given `path`. The file should contain raw SSZ bytes (i.e., no
/// ASCII encoding or schema).
pub fn state_from_ssz_file<E: EthSpec>(path: PathBuf) -> Result<BeaconState<E>, String> {
    File::open(path.clone())
        .map_err(move |e| format!("Unable to open SSZ genesis state file {:?}: {:?}", path, e))
        .and_then(|mut file| {
            let mut bytes = vec![];
            file.read_to_end(&mut bytes)
                .map_err(|e| format!("Failed to read SSZ file: {:?}", e))?;
            Ok(bytes)
        })
        .and_then(|bytes| {
            BeaconState::from_ssz_bytes(&bytes)
                .map_err(|e| format!("Unable to parse SSZ genesis state file: {:?}", e))
        })
}
