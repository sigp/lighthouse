use beacon_chain::BeaconChain as RawBeaconChain;
use beacon_chain::{
    parking_lot::{RwLockReadGuard, RwLockWriteGuard},
    types::{BeaconState, ChainSpec, Signature},
    AttestationValidationError, BlockProductionError,
};
pub use beacon_chain::{BeaconChainError, BeaconChainTypes, BlockProcessingOutcome};
use types::{Attestation, AttestationData, BeaconBlock};

/// The RPC's API to the beacon chain.
pub trait BeaconChain<T: BeaconChainTypes>: Send + Sync {
    fn get_spec(&self) -> &ChainSpec;

    fn get_state(&self) -> RwLockReadGuard<BeaconState<T::EthSpec>>;

    fn get_mut_state(&self) -> RwLockWriteGuard<BeaconState<T::EthSpec>>;

    fn process_block(&self, block: BeaconBlock)
        -> Result<BlockProcessingOutcome, BeaconChainError>;

    fn produce_block(
        &self,
        randao_reveal: Signature,
    ) -> Result<(BeaconBlock, BeaconState<T::EthSpec>), BlockProductionError>;

    fn produce_attestation_data(&self, shard: u64) -> Result<AttestationData, BeaconChainError>;

    fn process_attestation(
        &self,
        attestation: Attestation,
    ) -> Result<(), AttestationValidationError>;
}

impl<T: BeaconChainTypes> BeaconChain<T> for RawBeaconChain<T> {
    fn get_spec(&self) -> &ChainSpec {
        &self.spec
    }

    fn get_state(&self) -> RwLockReadGuard<BeaconState<T::EthSpec>> {
        self.state.read()
    }

    fn get_mut_state(&self) -> RwLockWriteGuard<BeaconState<T::EthSpec>> {
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
    ) -> Result<(BeaconBlock, BeaconState<T::EthSpec>), BlockProductionError> {
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
