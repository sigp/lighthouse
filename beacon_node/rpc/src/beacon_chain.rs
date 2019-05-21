use beacon_chain::BeaconChain as RawBeaconChain;
use beacon_chain::{
    db::Store,
    fork_choice::ForkChoice,
    parking_lot::{RwLockReadGuard, RwLockWriteGuard},
    slot_clock::SlotClock,
    types::{BeaconState, ChainSpec, Signature},
    AttestationValidationError, BlockProductionError,
};
pub use beacon_chain::{BeaconChainError, BlockProcessingOutcome};
use types::{Attestation, AttestationData, BeaconBlock, EthSpec};

/// The RPC's API to the beacon chain.
pub trait BeaconChain<E: EthSpec>: Send + Sync {
    fn get_spec(&self) -> &ChainSpec;

    fn get_state(&self) -> RwLockReadGuard<BeaconState<E>>;

    fn get_mut_state(&self) -> RwLockWriteGuard<BeaconState<E>>;

    fn process_block(&self, block: BeaconBlock)
        -> Result<BlockProcessingOutcome, BeaconChainError>;

    fn produce_block(
        &self,
        randao_reveal: Signature,
    ) -> Result<(BeaconBlock, BeaconState<E>), BlockProductionError>;

    fn produce_attestation_data(&self, shard: u64) -> Result<AttestationData, BeaconChainError>;

    fn process_attestation(
        &self,
        attestation: Attestation,
    ) -> Result<(), AttestationValidationError>;
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

    fn get_mut_state(&self) -> RwLockWriteGuard<BeaconState<E>> {
        self.state.write()
    }

    fn process_block(
        &self,
        block: BeaconBlock,
    ) -> Result<BlockProcessingOutcome, BeaconChainError> {
        self.process_block(block)
    }

    fn produce_block(
        &self,
        randao_reveal: Signature,
    ) -> Result<(BeaconBlock, BeaconState<E>), BlockProductionError> {
        self.produce_block(randao_reveal)
    }

    fn produce_attestation_data(&self, shard: u64) -> Result<AttestationData, BeaconChainError> {
        self.produce_attestation_data(shard)
    }

    fn process_attestation(
        &self,
        attestation: Attestation,
    ) -> Result<(), AttestationValidationError> {
        self.process_attestation(attestation)
    }
}
