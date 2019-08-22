use crate::BeaconChainTypes;
use std::fs::File;
use std::path::PathBuf;
use std::time::SystemTime;
use types::{
    test_utils::TestingBeaconStateBuilder, BeaconBlock, BeaconState, ChainSpec, EthSpec, Hash256,
};

pub struct BeaconChainBuilder<T: BeaconChainTypes> {
    genesis_state: BeaconState<T::EthSpec>,
    genesis_block: BeaconBlock<T::EthSpec>,
    spec: ChainSpec,
}

impl<T: BeaconChainTypes> BeaconChainBuilder<T> {
    pub fn recent_genesis(validator_count: usize, spec: ChainSpec) -> Self {
        Self::quick_start(recent_genesis_time(), validator_count, spec)
    }

    pub fn quick_start(genesis_time: u64, validator_count: usize, spec: ChainSpec) -> Self {
        let (mut genesis_state, _keypairs) =
            TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(validator_count, &spec)
                .build();

        genesis_state.genesis_time = genesis_time;

        Self::from_genesis_state(genesis_state, spec)
    }

    pub fn yaml_state(file: PathBuf, spec: ChainSpec) -> Result<Self, String> {
        let file = File::open(file.clone())
            .map_err(|e| format!("Unable to open YAML genesis state file {:?}: {:?}", file, e))?;

        let genesis_state = serde_yaml::from_reader(file)
            .map_err(|e| format!("Unable to parse YAML genesis state file: {:?}", e))?;

        Ok(Self::from_genesis_state(genesis_state, spec))
    }

    pub fn from_genesis_state(genesis_state: BeaconState<T::EthSpec>, spec: ChainSpec) -> Self {
        Self {
            genesis_block: genesis_block(&genesis_state, &spec),
            genesis_state,
            spec,
        }
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
fn recent_genesis_time() -> u64 {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let secs_after_last_period = now.checked_rem(30 * 60).unwrap_or(0);
    // genesis is now the last 30 minute block.
    now - secs_after_last_period
}
