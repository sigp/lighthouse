extern crate db;
extern crate naive_fork_choice;
extern crate genesis;
extern crate spec;
extern crate ssz;
extern crate ssz_helpers;
extern crate state_transition;
extern crate types;
extern crate validator_induction;
extern crate validator_shuffling;

mod block_processing;
mod maps;
mod stores;
mod transition;

use db::ClientDB;
use genesis::{genesis_beacon_state, GenesisError};
use maps::{generate_attester_and_proposer_maps, AttesterAndProposerMapError};
use spec::ChainSpec;
use std::collections::HashMap;
use std::sync::Arc;
use stores::BeaconChainStore;
use types::{AttesterMap, BeaconState, Hash256, ProposerMap};

#[derive(Debug, PartialEq)]
pub enum BeaconChainError {
    InvalidGenesis,
    InsufficientValidators,
    UnableToGenerateMaps(AttesterAndProposerMapError),
    GenesisError(GenesisError),
    DBError(String),
}

pub struct BeaconChain<T: ClientDB + Sized> {
    /// The last slot which has been finalized, this is common to all forks.
    pub last_finalized_slot: u64,
    /// A vec of all block heads (tips of chains).
    pub head_block_hashes: Vec<Hash256>,
    /// The index of the canonical block in `head_block_hashes`.
    pub canonical_head_block_hash: usize,
    /// An in-memory map of root hash to beacon state.
    pub beacon_states: HashMap<Hash256, BeaconState>,
    /// A map of crystallized state to a proposer and attester map.
    pub attester_proposer_maps: HashMap<Hash256, (Arc<AttesterMap>, Arc<ProposerMap>)>,
    /// A collection of database stores used by the chain.
    pub store: BeaconChainStore<T>,
    /// The chain configuration.
    pub spec: ChainSpec,
}

impl<T> BeaconChain<T>
where
    T: ClientDB + Sized,
{
    pub fn new(store: BeaconChainStore<T>, spec: ChainSpec) -> Result<Self, BeaconChainError> {
        if spec.initial_validators.is_empty() {
            return Err(BeaconChainError::InsufficientValidators);
        }

        /*
         * Generate and process the genesis state.
         */
        let genesis_state = genesis_beacon_state(&spec)?;
        let mut beacon_states = HashMap::new();
        beacon_states.insert(genesis_state.canonical_root(), genesis_state.clone());

        // TODO: implement genesis block
        // https://github.com/sigp/lighthouse/issues/105
        let canonical_latest_block_hash = Hash256::zero();

        let head_block_hashes = vec![canonical_latest_block_hash];
        let canonical_head_block_hash = 0;

        let mut attester_proposer_maps = HashMap::new();

        let (attester_map, proposer_map) = generate_attester_and_proposer_maps(
            &genesis_state.shard_committees_at_slots,
            0,
        )?;

        attester_proposer_maps.insert(
            canonical_latest_block_hash,
            (Arc::new(attester_map), Arc::new(proposer_map)),
        );

        Ok(Self {
            last_finalized_slot: 0,
            head_block_hashes,
            canonical_head_block_hash,
            beacon_states,
            attester_proposer_maps,
            store,
            spec,
        })
    }

    pub fn canonical_block_hash(&self) -> Hash256 {
        self.head_block_hashes[self.canonical_head_block_hash]
    }
}

impl From<AttesterAndProposerMapError> for BeaconChainError {
    fn from(e: AttesterAndProposerMapError) -> BeaconChainError {
        BeaconChainError::UnableToGenerateMaps(e)
    }
}

impl From<GenesisError> for BeaconChainError {
    fn from(e: GenesisError) -> BeaconChainError {
        BeaconChainError::GenesisError(e)
    }
}
