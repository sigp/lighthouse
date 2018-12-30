mod block_processing;
mod block_production;
mod maps;
mod stores;

use db::{
    stores::{BeaconBlockStore, BeaconStateStore},
    ClientDB, DBError,
};
use genesis::{genesis_beacon_block, genesis_beacon_state, GenesisError};
use slot_clock::{SlotClock, TestingSlotClockError};
use spec::ChainSpec;
use ssz::ssz_encode;
use std::collections::HashSet;
use std::sync::Arc;
use types::Hash256;

pub use crate::block_processing::Outcome as BlockProcessingOutcome;

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
        leaf_blocks.insert(block_root.clone());

        Ok(Self {
            block_store,
            state_store,
            slot_clock,
            leaf_blocks,
            canonical_leaf_block: block_root,
            spec,
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
