mod attestation_targets;
mod block_graph;
pub mod block_processing;
pub mod block_production;
mod canonical_head;
pub mod dump;
mod finalized_head;
mod info;
mod lmd_ghost;
mod state_transition;

use self::attestation_targets::AttestationTargets;
use self::block_graph::BlockGraph;
use db::{
    stores::{BeaconBlockStore, BeaconStateStore},
    ClientDB, DBError,
};
use genesis::{genesis_beacon_block, genesis_beacon_state, GenesisError};
use slot_clock::SlotClock;
use ssz::ssz_encode;
use std::sync::{Arc, RwLock};
use types::{BeaconBlock, BeaconState, ChainSpec, Hash256};

pub use self::block_processing::Outcome as BlockProcessingOutcome;

#[derive(Debug, PartialEq)]
pub enum BeaconChainError {
    InsufficientValidators,
    GenesisError(GenesisError),
    DBError(String),
}

pub struct CheckPoint {
    beacon_block: BeaconBlock,
    beacon_block_root: Hash256,
    beacon_state: BeaconState,
    beacon_state_root: Hash256,
}

impl CheckPoint {
    pub fn new(
        beacon_block: BeaconBlock,
        beacon_block_root: Hash256,
        beacon_state: BeaconState,
        beacon_state_root: Hash256,
    ) -> Self {
        Self {
            beacon_block,
            beacon_block_root,
            beacon_state,
            beacon_state_root,
        }
    }

    pub fn update(
        &mut self,
        beacon_block: BeaconBlock,
        beacon_block_root: Hash256,
        beacon_state: BeaconState,
        beacon_state_root: Hash256,
    ) {
        self.beacon_block = beacon_block;
        self.beacon_block_root = beacon_block_root;
        self.beacon_state = beacon_state;
        self.beacon_state_root = beacon_state_root;
    }
}

pub struct BeaconChain<T: ClientDB + Sized, U: SlotClock> {
    pub block_store: Arc<BeaconBlockStore<T>>,
    pub state_store: Arc<BeaconStateStore<T>>,
    pub slot_clock: U,
    pub block_graph: BlockGraph,
    canonical_head: RwLock<CheckPoint>,
    finalized_head: RwLock<CheckPoint>,
    pub latest_attestation_targets: RwLock<AttestationTargets>,
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

        let block_graph = BlockGraph::new();
        block_graph.add_leaf(&Hash256::zero(), block_root.clone());

        let finalized_head = RwLock::new(CheckPoint::new(
            genesis_block.clone(),
            block_root.clone(),
            genesis_state.clone(),
            state_root.clone(),
        ));
        let canonical_head = RwLock::new(CheckPoint::new(
            genesis_block.clone(),
            block_root.clone(),
            genesis_state.clone(),
            state_root.clone(),
        ));

        let latest_attestation_targets = RwLock::new(AttestationTargets::new());

        Ok(Self {
            block_store,
            state_store,
            slot_clock,
            block_graph,
            finalized_head,
            canonical_head,
            latest_attestation_targets,
            spec: spec,
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
