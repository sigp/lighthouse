use super::*;
use crate::case_result::compare_beacon_state_results_without_caches;
use crate::decode::{ssz_decode_file, ssz_decode_state, yaml_decode_file};
use serde_derive::Deserialize;
use state_processing::initialize_beacon_state_from_eth1;
use std::path::PathBuf;
use types::{BeaconState, Deposit, EthSpec, ForkName, Hash256};

#[derive(Debug, Clone, Deserialize)]
struct Metadata {
    deposits_count: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct Eth1 {
    eth1_block_hash: Hash256,
    eth1_timestamp: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(bound = "E: EthSpec")]
pub struct GenesisInitialization<E: EthSpec> {
    pub path: PathBuf,
    pub eth1_block_hash: Hash256,
    pub eth1_timestamp: u64,
    pub deposits: Vec<Deposit>,
    pub state: Option<BeaconState<E>>,
}

impl<E: EthSpec> LoadCase for GenesisInitialization<E> {
    fn load_from_dir(path: &Path, fork_name: ForkName) -> Result<Self, Error> {
        let Eth1 {
            eth1_block_hash,
            eth1_timestamp,
        } = yaml_decode_file(&path.join("eth1.yaml"))?;
        let meta: Metadata = yaml_decode_file(&path.join("meta.yaml"))?;
        let deposits: Vec<Deposit> = (0..meta.deposits_count)
            .map(|i| {
                let filename = format!("deposits_{}.ssz_snappy", i);
                ssz_decode_file(&path.join(filename))
            })
            .collect::<Result<_, _>>()?;
        let spec = &testing_spec::<E>(fork_name);
        let state = ssz_decode_state(&path.join("state.ssz_snappy"), spec)?;

        Ok(Self {
            path: path.into(),
            eth1_block_hash,
            eth1_timestamp,
            deposits,
            state: Some(state),
        })
    }
}

impl<E: EthSpec> Case for GenesisInitialization<E> {
    fn is_enabled_for_fork(fork_name: ForkName) -> bool {
        // Altair genesis and later requires real crypto.
        fork_name == ForkName::Base || cfg!(not(feature = "fake_crypto"))
    }

    fn result(&self, _case_index: usize, fork_name: ForkName) -> Result<(), Error> {
        let spec = &testing_spec::<E>(fork_name);

        let mut result = initialize_beacon_state_from_eth1(
            self.eth1_block_hash,
            self.eth1_timestamp,
            self.deposits.clone(),
            spec,
        );

        let mut expected = self.state.clone();

        compare_beacon_state_results_without_caches(&mut result, &mut expected)
    }
}
