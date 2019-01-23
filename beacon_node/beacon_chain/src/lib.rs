mod block_processing;
mod block_production;
mod lmd_ghost;
mod state_transition;

use db::{
    stores::{BeaconBlockStore, BeaconStateStore},
    ClientDB, DBError,
};
use genesis::{genesis_beacon_block, genesis_beacon_state, GenesisError};
use slot_clock::SlotClock;
use spec::ChainSpec;
use ssz::ssz_encode;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use types::Hash256;

pub use self::block_processing::Outcome as BlockProcessingOutcome;

#[derive(Debug, PartialEq)]
pub struct CheckPoint {
    block_root: Hash256,
    state_root: Hash256,
    slot: u64,
}

#[derive(Debug, PartialEq)]
pub enum BeaconChainError {
    InsufficientValidators,
    GenesisError(GenesisError),
    DBError(String),
}

pub struct BeaconChain<T: ClientDB + Sized, U: SlotClock> {
    pub block_store: Arc<BeaconBlockStore<T>>,
    pub state_store: Arc<BeaconStateStore<T>>,
    pub slot_clock: U,
    pub leaf_blocks: HashSet<Hash256>,
    pub canonical_leaf_block: Hash256,
    pub spec: ChainSpec,
    latest_attestation_targets: HashMap<usize, Hash256>,
    finalized_checkpoint: CheckPoint,
}

impl<T, U> BeaconChain<T, U>
where
    T: ClientDB,
    U: SlotClock,
{
    pub fn genesis(
        state_store: Arc<BeaconStateStore<T>>,
        block_store: Arc<BeaconBlockStore<T>>,
        slot_clock: U,
        spec: ChainSpec,
    ) -> Result<Self, BeaconChainError> {
        if spec.initial_validators.is_empty() {
            return Err(BeaconChainError::InsufficientValidators);
        }

        let genesis_state = genesis_beacon_state(&spec)?;
        let state_root = genesis_state.canonical_root();
        state_store.put(&state_root, &ssz_encode(&genesis_state)[..])?;

        let genesis_block = genesis_beacon_block(state_root, &spec);
        let block_root = genesis_block.canonical_root();
        block_store.put(&block_root, &ssz_encode(&genesis_block)[..])?;

        let mut leaf_blocks = HashSet::new();
        leaf_blocks.insert(block_root);

        let finalized_checkpoint = CheckPoint {
            block_root,
            state_root,
            slot: genesis_block.slot,
        };

        Ok(Self {
            block_store,
            state_store,
            slot_clock,
            leaf_blocks,
            canonical_leaf_block: block_root,
            spec,
            latest_attestation_targets: HashMap::new(),
            finalized_checkpoint,
        })
    }
}

impl From<DBError> for BeaconChainError {
    fn from(e: DBError) -> BeaconChainError {
        BeaconChainError::DBError(e.message)
    }
}

impl From<GenesisError> for BeaconChainError {
    fn from(e: GenesisError) -> BeaconChainError {
        BeaconChainError::GenesisError(e)
    }
}
