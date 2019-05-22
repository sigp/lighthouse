use beacon_chain::BeaconChain as RawBeaconChain;
use beacon_chain::{
    fork_choice::ForkChoice,
    parking_lot::RwLockReadGuard,
    slot_clock::SlotClock,
    store::Store,
    types::{BeaconState, ChainSpec},
    AttestationValidationError, CheckPoint,
};
use eth2_libp2p::rpc::HelloMessage;
use types::{
    Attestation, BeaconBlock, BeaconBlockBody, BeaconBlockHeader, Epoch, EthSpec, Hash256, Slot,
};

pub use beacon_chain::{BeaconChainError, BlockProcessingOutcome, InvalidBlock};

/// The network's API to the beacon chain.
pub trait BeaconChain<E: EthSpec>: Send + Sync {
    fn get_spec(&self) -> &ChainSpec;

    fn get_state(&self) -> RwLockReadGuard<BeaconState<E>>;

    fn slot(&self) -> Slot;

    fn head(&self) -> RwLockReadGuard<CheckPoint<E>>;

    fn get_block(&self, block_root: &Hash256) -> Result<Option<BeaconBlock>, BeaconChainError>;

    fn best_slot(&self) -> Slot;

    fn best_block_root(&self) -> Hash256;

    fn finalized_head(&self) -> RwLockReadGuard<CheckPoint<E>>;

    fn finalized_epoch(&self) -> Epoch;

    fn hello_message(&self) -> HelloMessage;

    fn process_block(&self, block: BeaconBlock)
        -> Result<BlockProcessingOutcome, BeaconChainError>;

    fn process_attestation(
        &self,
        attestation: Attestation,
    ) -> Result<(), AttestationValidationError>;

    fn get_block_roots(
        &self,
        start_slot: Slot,
        count: usize,
        skip: usize,
    ) -> Result<Vec<Hash256>, BeaconChainError>;

    fn get_block_headers(
        &self,
        start_slot: Slot,
        count: usize,
        skip: usize,
    ) -> Result<Vec<BeaconBlockHeader>, BeaconChainError>;

    fn get_block_bodies(&self, roots: &[Hash256])
        -> Result<Vec<BeaconBlockBody>, BeaconChainError>;

    fn is_new_block_root(&self, beacon_block_root: &Hash256) -> Result<bool, BeaconChainError>;
}

impl<T, U, F, E> BeaconChain<E> for RawBeaconChain<T, U, F, E>
where
    T: Store,
    U: SlotClock,
    F: ForkChoice,
    E: EthSpec,
{
    fn get_spec(&self) -> &ChainSpec {
        &self.spec
    }

    fn get_state(&self) -> RwLockReadGuard<BeaconState<E>> {
        self.state.read()
    }

    fn slot(&self) -> Slot {
        self.get_state().slot
    }

    fn head(&self) -> RwLockReadGuard<CheckPoint<E>> {
        self.head()
    }

    fn get_block(&self, block_root: &Hash256) -> Result<Option<BeaconBlock>, BeaconChainError> {
        self.get_block(block_root)
    }

    fn finalized_epoch(&self) -> Epoch {
        self.get_state().finalized_epoch
    }

    fn finalized_head(&self) -> RwLockReadGuard<CheckPoint<E>> {
        self.finalized_head()
    }

    fn best_slot(&self) -> Slot {
        self.head().beacon_block.slot
    }

    fn best_block_root(&self) -> Hash256 {
        self.head().beacon_block_root
    }

    fn hello_message(&self) -> HelloMessage {
        let spec = self.get_spec();
        let state = self.get_state();

        HelloMessage {
            network_id: spec.chain_id,
            latest_finalized_root: state.finalized_root,
            latest_finalized_epoch: state.finalized_epoch,
            best_root: self.best_block_root(),
            best_slot: self.best_slot(),
        }
    }

    fn process_block(
        &self,
        block: BeaconBlock,
    ) -> Result<BlockProcessingOutcome, BeaconChainError> {
        self.process_block(block)
    }

    fn process_attestation(
        &self,
        attestation: Attestation,
    ) -> Result<(), AttestationValidationError> {
        self.process_attestation(attestation)
    }

    fn get_block_roots(
        &self,
        start_slot: Slot,
        count: usize,
        skip: usize,
    ) -> Result<Vec<Hash256>, BeaconChainError> {
        self.get_block_roots(start_slot, count, skip)
    }

    fn get_block_headers(
        &self,
        start_slot: Slot,
        count: usize,
        skip: usize,
    ) -> Result<Vec<BeaconBlockHeader>, BeaconChainError> {
        let roots = self.get_block_roots(start_slot, count, skip)?;
        self.get_block_headers(&roots)
    }

    fn get_block_bodies(
        &self,
        roots: &[Hash256],
    ) -> Result<Vec<BeaconBlockBody>, BeaconChainError> {
        self.get_block_bodies(roots)
    }

    fn is_new_block_root(&self, beacon_block_root: &Hash256) -> Result<bool, BeaconChainError> {
        self.is_new_block_root(beacon_block_root)
    }
}
