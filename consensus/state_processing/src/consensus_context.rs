use crate::common::get_indexed_attestation;
use crate::per_block_processing::errors::{AttestationInvalid, BlockOperationError};
use crate::EpochCacheError;
use std::collections::{hash_map::Entry, HashMap};
use tree_hash::TreeHash;
use types::{
    AbstractExecPayload, Attestation, AttestationData, BeaconState, BeaconStateError, BitList,
    ChainSpec, Epoch, EthSpec, Hash256, IndexedAttestation, SignedBeaconBlock, Slot,
};

#[derive(Debug, PartialEq, Clone)]
pub struct ConsensusContext<E: EthSpec> {
    /// Slot to act as an identifier/safeguard
    pub slot: Slot,
    /// Previous epoch of the `slot` precomputed for optimization purpose.
    pub previous_epoch: Epoch,
    /// Current epoch of the `slot` precomputed for optimization purpose.
    pub current_epoch: Epoch,
    /// Proposer index of the block at `slot`.
    pub proposer_index: Option<u64>,
    /// Block root of the block at `slot`.
    pub current_block_root: Option<Hash256>,
    /// Cache of indexed attestations constructed during block processing.
    pub indexed_attestations:
        HashMap<(AttestationData, BitList<E::MaxValidatorsPerCommittee>), IndexedAttestation<E>>,
}

#[derive(Debug, PartialEq, Clone)]
pub enum ContextError {
    BeaconState(BeaconStateError),
    EpochCache(EpochCacheError),
    SlotMismatch { slot: Slot, expected: Slot },
    EpochMismatch { epoch: Epoch, expected: Epoch },
}

impl From<BeaconStateError> for ContextError {
    fn from(e: BeaconStateError) -> Self {
        Self::BeaconState(e)
    }
}

impl From<EpochCacheError> for ContextError {
    fn from(e: EpochCacheError) -> Self {
        Self::EpochCache(e)
    }
}

impl<E: EthSpec> ConsensusContext<E> {
    pub fn new(slot: Slot) -> Self {
        let current_epoch = slot.epoch(E::slots_per_epoch());
        let previous_epoch = current_epoch.saturating_sub(1u64);
        Self {
            slot,
            previous_epoch,
            current_epoch,
            proposer_index: None,
            current_block_root: None,
            indexed_attestations: HashMap::new(),
        }
    }

    #[must_use]
    pub fn set_proposer_index(mut self, proposer_index: u64) -> Self {
        self.proposer_index = Some(proposer_index);
        self
    }

    /// Strict method for fetching the proposer index.
    ///
    /// Gets the proposer index for `self.slot` while ensuring that it matches `state.slot()`. This
    /// method should be used in block processing and almost everywhere the proposer index is
    /// required. If the slot check is too restrictive, see `get_proposer_index_from_epoch_state`.
    pub fn get_proposer_index(
        &mut self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<u64, ContextError> {
        self.check_slot(state.slot())?;
        self.get_proposer_index_no_checks(state, spec)
    }

    /// More liberal method for fetching the proposer index.
    ///
    /// Fetches the proposer index for `self.slot` but does not require the state to be from an
    /// exactly matching slot (merely a matching epoch). This is useful in batch verification where
    /// we want to extract the proposer index from a single state for every slot in the epoch.
    pub fn get_proposer_index_from_epoch_state(
        &mut self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<u64, ContextError> {
        self.check_epoch(state.current_epoch())?;
        self.get_proposer_index_no_checks(state, spec)
    }

    fn get_proposer_index_no_checks(
        &mut self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<u64, ContextError> {
        if let Some(proposer_index) = self.proposer_index {
            return Ok(proposer_index);
        }

        let proposer_index = state.get_beacon_proposer_index(self.slot, spec)? as u64;
        self.proposer_index = Some(proposer_index);
        Ok(proposer_index)
    }

    #[must_use]
    pub fn set_current_block_root(mut self, block_root: Hash256) -> Self {
        self.current_block_root = Some(block_root);
        self
    }

    pub fn get_current_block_root<Payload: AbstractExecPayload<E>>(
        &mut self,
        block: &SignedBeaconBlock<E, Payload>,
    ) -> Result<Hash256, ContextError> {
        self.check_slot(block.slot())?;

        if let Some(current_block_root) = self.current_block_root {
            return Ok(current_block_root);
        }

        let current_block_root = block.message().tree_hash_root();
        self.current_block_root = Some(current_block_root);
        Ok(current_block_root)
    }

    fn check_slot(&self, slot: Slot) -> Result<(), ContextError> {
        if slot == self.slot {
            Ok(())
        } else {
            Err(ContextError::SlotMismatch {
                slot,
                expected: self.slot,
            })
        }
    }

    fn check_epoch(&self, epoch: Epoch) -> Result<(), ContextError> {
        let expected = self.slot.epoch(E::slots_per_epoch());
        if epoch == expected {
            Ok(())
        } else {
            Err(ContextError::EpochMismatch { epoch, expected })
        }
    }

    pub fn get_indexed_attestation(
        &mut self,
        state: &BeaconState<E>,
        attestation: &Attestation<E>,
    ) -> Result<&IndexedAttestation<E>, BlockOperationError<AttestationInvalid>> {
        let key = (
            attestation.data.clone(),
            attestation.aggregation_bits.clone(),
        );

        match self.indexed_attestations.entry(key) {
            Entry::Occupied(occupied) => Ok(occupied.into_mut()),
            Entry::Vacant(vacant) => {
                let committee =
                    state.get_beacon_committee(attestation.data.slot, attestation.data.index)?;
                let indexed_attestation =
                    get_indexed_attestation(committee.committee, attestation)?;
                Ok(vacant.insert(indexed_attestation))
            }
        }
    }

    pub fn num_cached_indexed_attestations(&self) -> usize {
        self.indexed_attestations.len()
    }

    #[must_use]
    pub fn set_indexed_attestations(
        mut self,
        attestations: HashMap<
            (AttestationData, BitList<E::MaxValidatorsPerCommittee>),
            IndexedAttestation<E>,
        >,
    ) -> Self {
        self.indexed_attestations = attestations;
        self
    }
}
