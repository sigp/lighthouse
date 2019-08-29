use super::bootstrapper::Bootstrapper;
use crate::{BeaconChain, BeaconChainTypes};
use slog::Logger;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use types::{test_utils::TestingBeaconStateBuilder, BeaconBlock, BeaconState, ChainSpec, EthSpec};

enum BuildStrategy<T: BeaconChainTypes> {
    FromGenesis {
        genesis_state: Box<BeaconState<T::EthSpec>>,
        genesis_block: Box<BeaconBlock<T::EthSpec>>,
    },
    LoadFromStore,
}

pub struct BeaconChainBuilder<T: BeaconChainTypes> {
    build_strategy: BuildStrategy<T>,
    spec: ChainSpec,
    log: Logger,
}

impl<T: BeaconChainTypes> BeaconChainBuilder<T> {
    pub fn recent_genesis(
        validator_count: usize,
        minutes: u64,
        spec: ChainSpec,
        log: Logger,
    ) -> Self {
        Self::quick_start(recent_genesis_time(minutes), validator_count, spec, log)
    }

    pub fn quick_start(
        genesis_time: u64,
        validator_count: usize,
        spec: ChainSpec,
        log: Logger,
    ) -> Self {
        let (mut genesis_state, _keypairs) =
            TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(validator_count, &spec)
                .build();

        genesis_state.genesis_time = genesis_time;

        Self::from_genesis_state(genesis_state, spec, log)
    }

    pub fn yaml_state(file: &PathBuf, spec: ChainSpec, log: Logger) -> Result<Self, String> {
        let file = File::open(file.clone())
            .map_err(|e| format!("Unable to open YAML genesis state file {:?}: {:?}", file, e))?;

        let genesis_state = serde_yaml::from_reader(file)
            .map_err(|e| format!("Unable to parse YAML genesis state file: {:?}", e))?;

        Ok(Self::from_genesis_state(genesis_state, spec, log))
    }

    pub fn http_bootstrap(server: &str, spec: ChainSpec, log: Logger) -> Result<Self, String> {
        let bootstrapper = Bootstrapper::from_server_string(server.to_string())
            .map_err(|e| format!("Failed to initialize bootstrap client: {}", e))?;

        let (genesis_state, genesis_block) = bootstrapper
            .genesis()
            .map_err(|e| format!("Failed to bootstrap genesis state: {}", e))?;

        Ok(Self {
            build_strategy: BuildStrategy::FromGenesis {
                genesis_block: Box::new(genesis_block),
                genesis_state: Box::new(genesis_state),
            },
            spec,
            log,
        })
    }

    fn from_genesis_state(
        genesis_state: BeaconState<T::EthSpec>,
        spec: ChainSpec,
        log: Logger,
    ) -> Self {
        Self {
            build_strategy: BuildStrategy::FromGenesis {
                genesis_block: Box::new(genesis_block(&genesis_state, &spec)),
                genesis_state: Box::new(genesis_state),
            },
            spec,
            log,
        }
    }

    pub fn from_store(spec: ChainSpec, log: Logger) -> Self {
        Self {
            build_strategy: BuildStrategy::LoadFromStore,
            spec,
            log,
        }
    }

    pub fn build(self, store: Arc<T::Store>) -> Result<BeaconChain<T>, String> {
        Ok(match self.build_strategy {
            BuildStrategy::LoadFromStore => BeaconChain::from_store(store, self.spec, self.log)
                .map_err(|e| format!("Error loading BeaconChain from database: {:?}", e))?
                .ok_or_else(|| format!("Unable to find exising BeaconChain in database."))?,
            BuildStrategy::FromGenesis {
                genesis_block,
                genesis_state,
            } => BeaconChain::from_genesis(
                store,
                genesis_state.as_ref().clone(),
                genesis_block.as_ref().clone(),
                self.spec,
                self.log,
            )
            .map_err(|e| format!("Failed to initialize new beacon chain: {:?}", e))?,
        })
    }
}

fn genesis_block<T: EthSpec>(genesis_state: &BeaconState<T>, spec: &ChainSpec) -> BeaconBlock<T> {
    let mut genesis_block = BeaconBlock::empty(&spec);

    genesis_block.state_root = genesis_state.canonical_root();

    genesis_block
}

/// Returns the system time, mod 30 minutes.
///
/// Used for easily creating testnets.
fn recent_genesis_time(minutes: u64) -> u64 {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let secs_after_last_period = now.checked_rem(minutes * 60).unwrap_or(0);
    // genesis is now the last 15 minute block.
    now - secs_after_last_period
}
