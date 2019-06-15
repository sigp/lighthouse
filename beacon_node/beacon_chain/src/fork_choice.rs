use crate::BeaconChain;
use lmd_ghost::LmdGhost;
use state_processing::common::get_attesting_indices_unsorted;
use std::marker::PhantomData;
use std::sync::Arc;
use store::Store;
use types::{Attestation, BeaconBlock, BeaconState, BeaconStateError, EthSpec, Hash256};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq)]
pub enum Error {
    BackendError(String),
    BeaconStateError(BeaconStateError),
}

pub struct ForkChoice<L, S, E> {
    backend: L,
    _phantom_a: PhantomData<S>,
    _phantom_b: PhantomData<E>,
}

impl<L, S, E> ForkChoice<L, S, E>
where
    L: LmdGhost<S, E>,
    S: Store,
    E: EthSpec,
{
    pub fn new(store: Arc<S>) -> Self {
        Self {
            backend: L::new(store),
            _phantom_a: PhantomData,
            _phantom_b: PhantomData,
        }
    }

    pub fn find_head(&self) -> Result<Hash256> {
        self.backend.find_head().map_err(Into::into)
    }

    pub fn process_attestation(
        &self,
        state: &BeaconState<E>,
        attestation: &Attestation,
    ) -> Result<()> {
        // Note: `get_attesting_indices_unsorted` requires that the beacon state caches be built.
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

    /// A helper function which runs `self.process_attestation` on all `Attestation` in the given `BeaconBlock`.
    ///
    /// Assumes the block (and therefore it's attestations) are valid. It is a logic error to
    /// provide an invalid block.
    pub fn process_block(&self, state: &BeaconState<E>, block: &BeaconBlock) -> Result<()> {
        // Note: we never count the block as a latest message, only attestations.
        //
        // I (Paul H) do not have an explicit reference to this, however I derive it from this
        // document:
        //
        // https://github.com/ethereum/eth2.0-specs/blob/v0.7.0/specs/core/0_fork-choice.md
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

impl From<String> for Error {
    fn from(e: String) -> Error {
        Error::BackendError(e)
    }
}
