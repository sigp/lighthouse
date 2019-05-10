use beacon_chain::BeaconChain as RawBeaconChain;
use beacon_chain::{
    db::ClientDB,
    fork_choice::ForkChoice,
    parking_lot::{RwLockReadGuard, RwLockWriteGuard},
    slot_clock::SlotClock,
    types::{BeaconState, ChainSpec, Signature},
    AttestationValidationError, BlockProductionError,
};
pub use beacon_chain::{BeaconChainError, BlockProcessingOutcome};
use types::{Attestation, AttestationData, BeaconBlock, EthSpec};

/// The RPC's API to the beacon chain.
pub trait BeaconChain<B: EthSpec>: Send + Sync {
    fn get_spec(&self) -> &ChainSpec;

    fn get_state(&self) -> RwLockReadGuard<BeaconState<B>>;

    fn get_mut_state(&self) -> RwLockWriteGuard<BeaconState<B>>;

    fn process_block(&self, block: BeaconBlock)
        -> Result<BlockProcessingOutcome, BeaconChainError>;

    fn produce_block(
        &self,
        randao_reveal: Signature,
    ) -> Result<(BeaconBlock, BeaconState<B>), BlockProductionError>;

    fn produce_attestation_data(&self, shard: u64) -> Result<AttestationData, BeaconChainError>;

    fn process_attestation(
        &self,
        attestation: Attestation,
    ) -> Result<(), AttestationValidationError>;
}

impl<T, U, F, B> BeaconChain<B> for RawBeaconChain<T, U, F, B>
where
    T: ClientDB + Sized,
    U: SlotClock,
    F: ForkChoice,
    B: EthSpec,
{
    fn get_spec(&self) -> &ChainSpec {
        &self.spec
    }

    fn get_state(&self) -> RwLockReadGuard<BeaconState<B>> {
        self.state.read()
    }

    fn get_mut_state(&self) -> RwLockWriteGuard<BeaconState<B>> {
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
    ) -> Result<(BeaconBlock, BeaconState<B>), BlockProductionError> {
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
