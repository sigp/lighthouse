use std::marker::PhantomData;
use std::sync::Arc;
use tree_hash::TreeHash;
use types::{
    AbstractExecPayload, BeaconState, BeaconStateError, BlobsSidecar, ChainSpec, EthSpec,
    ExecPayload, Hash256, SignedBeaconBlock, Slot,
};

#[derive(Debug)]
pub struct ConsensusContext<T: EthSpec> {
    /// Slot to act as an identifier/safeguard
    slot: Slot,
    /// Proposer index of the block at `slot`.
    proposer_index: Option<u64>,
    /// Block root of the block at `slot`.
    current_block_root: Option<Hash256>,
    /// Should only be populated if the sidecar has not been validated.
    blobs_sidecar: Option<Arc<BlobsSidecar<T>>>,
    /// Whether `validate_blobs_sidecar` has successfully passed.
    blobs_sidecar_validated: bool,
    /// Whether `verify_kzg_commitments_against_transactions` has successfully passed.
    blobs_verified_vs_txs: bool,
}

#[derive(Debug, PartialEq, Clone)]
pub enum ContextError {
    BeaconState(BeaconStateError),
    SlotMismatch { slot: Slot, expected: Slot },
}

impl From<BeaconStateError> for ContextError {
    fn from(e: BeaconStateError) -> Self {
        Self::BeaconState(e)
    }
}

impl<T: EthSpec> ConsensusContext<T> {
    pub fn new(slot: Slot) -> Self {
        Self {
            slot,
            proposer_index: None,
            current_block_root: None,
            blobs_sidecar: None,
            blobs_sidecar_validated: false,
            blobs_verified_vs_txs: false,
        }
    }

    pub fn set_proposer_index(mut self, proposer_index: u64) -> Self {
        self.proposer_index = Some(proposer_index);
        self
    }

    pub fn get_proposer_index(
        &mut self,
        state: &BeaconState<T>,
        spec: &ChainSpec,
    ) -> Result<u64, ContextError> {
        self.check_slot(state.slot())?;

        if let Some(proposer_index) = self.proposer_index {
            return Ok(proposer_index);
        }

        let proposer_index = state.get_beacon_proposer_index(self.slot, spec)? as u64;
        self.proposer_index = Some(proposer_index);
        Ok(proposer_index)
    }

    pub fn set_current_block_root(mut self, block_root: Hash256) -> Self {
        self.current_block_root = Some(block_root);
        self
    }

    pub fn get_current_block_root<Payload: AbstractExecPayload<T>>(
        &mut self,
        block: &SignedBeaconBlock<T, Payload>,
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

    pub fn set_blobs_sidecar_validated(mut self, blobs_sidecar_validated: bool) -> Self {
        self.blobs_sidecar_validated = blobs_sidecar_validated;
        self
    }

    pub fn set_blobs_verified_vs_txs(mut self, blobs_verified_vs_txs: bool) -> Self {
        self.blobs_verified_vs_txs = blobs_verified_vs_txs;
        self
    }

    pub fn blobs_sidecar_validated(&self) -> bool {
        self.blobs_sidecar_validated
    }

    pub fn blobs_verified_vs_txs(&self) -> bool {
        self.blobs_verified_vs_txs
    }

    pub fn set_blobs_sidecar(mut self, blobs_sidecar: Option<Arc<BlobsSidecar<T>>>) -> Self {
        self.blobs_sidecar = blobs_sidecar;
        self
    }
}
