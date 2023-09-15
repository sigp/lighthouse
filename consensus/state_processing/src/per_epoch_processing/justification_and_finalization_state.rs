use types::{BeaconState, BeaconStateError, BitVector, Checkpoint, Epoch, EthSpec, Hash256};

/// This is a subset of the `BeaconState` which is used to compute justification and finality
/// without modifying the `BeaconState`.
///
/// A `JustificationAndFinalizationState` can be created from a `BeaconState` to compute
/// justification/finality changes and then applied to a `BeaconState` to enshrine those changes.
#[must_use = "this value must be applied to a state or explicitly dropped"]
pub struct JustificationAndFinalizationState<T: EthSpec> {
    /*
     * Immutable fields.
     */
    previous_epoch: Epoch,
    previous_epoch_target_root: Result<Hash256, BeaconStateError>,
    current_epoch: Epoch,
    current_epoch_target_root: Result<Hash256, BeaconStateError>,
    /*
     * Mutable fields.
     */
    previous_justified_checkpoint: Checkpoint,
    current_justified_checkpoint: Checkpoint,
    finalized_checkpoint: Checkpoint,
    justification_bits: BitVector<T::JustificationBitsLength>,
}

impl<T: EthSpec> JustificationAndFinalizationState<T> {
    pub fn new(state: &BeaconState<T>) -> Self {
        let previous_epoch = state.previous_epoch();
        let current_epoch = state.current_epoch();
        Self {
            previous_epoch,
            previous_epoch_target_root: state.get_block_root_at_epoch(previous_epoch).copied(),
            current_epoch,
            current_epoch_target_root: state.get_block_root_at_epoch(current_epoch).copied(),
            previous_justified_checkpoint: state.previous_justified_checkpoint(),
            current_justified_checkpoint: state.current_justified_checkpoint(),
            finalized_checkpoint: state.finalized_checkpoint(),
            justification_bits: state.justification_bits().clone(),
        }
    }

    pub fn apply_changes_to_state(self, state: &mut BeaconState<T>) {
        let Self {
            /*
             * Immutable fields do not need to be used.
             */
            previous_epoch: _,
            previous_epoch_target_root: _,
            current_epoch: _,
            current_epoch_target_root: _,
            /*
             * Mutable fields *must* be used.
             */
            previous_justified_checkpoint,
            current_justified_checkpoint,
            finalized_checkpoint,
            justification_bits,
        } = self;

        *state.previous_justified_checkpoint_mut() = previous_justified_checkpoint;
        *state.current_justified_checkpoint_mut() = current_justified_checkpoint;
        *state.finalized_checkpoint_mut() = finalized_checkpoint;
        *state.justification_bits_mut() = justification_bits;
    }

    pub fn previous_epoch(&self) -> Epoch {
        self.previous_epoch
    }

    pub fn current_epoch(&self) -> Epoch {
        self.current_epoch
    }

    pub fn get_block_root_at_epoch(&self, epoch: Epoch) -> Result<Hash256, BeaconStateError> {
        if epoch == self.previous_epoch {
            self.previous_epoch_target_root.clone()
        } else if epoch == self.current_epoch {
            self.current_epoch_target_root.clone()
        } else {
            Err(BeaconStateError::SlotOutOfBounds)
        }
    }

    pub fn previous_justified_checkpoint(&self) -> Checkpoint {
        self.previous_justified_checkpoint
    }

    pub fn previous_justified_checkpoint_mut(&mut self) -> &mut Checkpoint {
        &mut self.previous_justified_checkpoint
    }

    pub fn current_justified_checkpoint_mut(&mut self) -> &mut Checkpoint {
        &mut self.current_justified_checkpoint
    }

    pub fn current_justified_checkpoint(&self) -> Checkpoint {
        self.current_justified_checkpoint
    }

    pub fn finalized_checkpoint(&self) -> Checkpoint {
        self.finalized_checkpoint
    }

    pub fn finalized_checkpoint_mut(&mut self) -> &mut Checkpoint {
        &mut self.finalized_checkpoint
    }

    pub fn justification_bits(&self) -> &BitVector<T::JustificationBitsLength> {
        &self.justification_bits
    }

    pub fn justification_bits_mut(&mut self) -> &mut BitVector<T::JustificationBitsLength> {
        &mut self.justification_bits
    }
}
