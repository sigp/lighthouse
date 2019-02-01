mod attestation_aggregator;
pub mod attestation_processing;
mod attestation_production;
mod attestation_targets;
mod block_graph;
pub mod block_processing;
pub mod block_production;
mod canonical_head;
mod checkpoint;
pub mod dump;
mod finalized_head;
mod info;
mod lmd_ghost;
mod state;

use self::attestation_targets::AttestationTargets;
use self::block_graph::BlockGraph;
use self::checkpoint::CheckPoint;
use attestation_aggregator::AttestationAggregator;
use db::{
    stores::{BeaconBlockStore, BeaconStateStore},
    ClientDB, DBError,
};
use genesis::{genesis_beacon_block, genesis_beacon_state, GenesisError};
use parking_lot::RwLock;
use slot_clock::SlotClock;
use ssz::ssz_encode;
use std::sync::Arc;
use types::{BeaconState, ChainSpec, Hash256};

pub use self::block_processing::Outcome as BlockProcessingOutcome;

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
    pub block_graph: BlockGraph,
    pub attestation_aggregator: RwLock<AttestationAggregator>,
    canonical_head: RwLock<CheckPoint>,
    finalized_head: RwLock<CheckPoint>,
    justified_head: RwLock<CheckPoint>,
    pub state: RwLock<BeaconState>,
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
        let justified_head = RwLock::new(CheckPoint::new(
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
        let attestation_aggregator = RwLock::new(AttestationAggregator::new());

        let latest_attestation_targets = RwLock::new(AttestationTargets::new());

        Ok(Self {
            block_store,
            state_store,
            slot_clock,
            block_graph,
            attestation_aggregator,
            state: RwLock::new(genesis_state.clone()),
            justified_head,
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
