pub mod reduced_tree;

use state_processing::common::get_attesting_indices_unsorted;
use std::marker::PhantomData;
use std::sync::Arc;
use types::{Attestation, BeaconBlock, BeaconState, BeaconStateError, EthSpec, Hash256, Slot};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq)]
pub enum Error {
    BackendError(String),
    BeaconStateError(BeaconStateError),
}

pub trait LmdGhostBackend<T, E: EthSpec>: Send + Sync {
    fn new(store: Arc<T>) -> Self;

    fn process_message(
        &self,
        validator_index: usize,
        block_hash: Hash256,
        block_slot: Slot,
    ) -> Result<()>;

    fn find_head(&self) -> Result<Hash256>;
}

pub struct ForkChoice<T, E> {
    backend: T,
    _phantom: PhantomData<E>,
}

impl<T, E> ForkChoice<T, E>
where
    T: LmdGhostBackend<T, E>,
    E: EthSpec,
{
    pub fn new(store: Arc<T>) -> Self {
        Self {
            backend: T::new(store),
            _phantom: PhantomData,
        }
    }

    pub fn find_head(&self) -> Result<Hash256> {
        self.backend.find_head()
    }

    pub fn process_attestation(
        &self,
        state: &BeaconState<E>,
        attestation: &Attestation,
    ) -> Result<()> {
        let validator_indices = get_attesting_indices_unsorted(
            state,
            &attestation.data,
            &attestation.aggregation_bitfield,
        )?;

        let block_hash = attestation.data.target_root;

        // TODO: what happens when the target root is not the same slot as the block?
        let block_slot = attestation
            .data
            .target_epoch
            .start_slot(E::slots_per_epoch());

        for validator_index in validator_indices {
            self.backend
                .process_message(validator_index, block_hash, block_slot)?;
        }

        Ok(())
    }

    pub fn process_block(
        &self,
        state: &BeaconState<E>,
        block: &BeaconBlock,
        block_hash: Hash256,
        block_proposer: usize,
    ) -> Result<()> {
        self.backend
            .process_message(block_proposer, block_hash, block.slot)?;

        for attestation in &block.body.attestations {
            self.process_attestation(state, attestation)?;
        }

        Ok(())
    }
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Error {
        Error::BeaconStateError(e)
    }
}
