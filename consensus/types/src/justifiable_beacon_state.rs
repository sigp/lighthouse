use crate::{BeaconState, Checkpoint, EthSpec};
use ssz_types::BitVector;

pub struct JustifiableBeaconState<E: EthSpec> {
    pub current_justified_checkpoint: Checkpoint,
    pub previous_justified_checkpoint: Checkpoint,
    pub justification_bits: BitVector<E::JustificationBitsLength>,
    pub finalized_checkpoint: Checkpoint,
}

impl<E: EthSpec> From<&mut BeaconState<E>> for JustifiableBeaconState<E> {
    fn from(state: &mut BeaconState<E>) -> Self {
        Self {
            current_justified_checkpoint: state.current_justified_checkpoint(),
            previous_justified_checkpoint: state.previous_justified_checkpoint(),
            justification_bits: state.justification_bits().clone(),
            finalized_checkpoint: state.finalized_checkpoint(),
        }
    }
}
