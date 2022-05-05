use crate::{Checkpoint, EthSpec};
use ssz_types::BitVector;

pub struct JustifiableBeaconState<T: EthSpec> {
    pub current_justified_checkpoint: Checkpoint,
    pub previous_justified_checkpoint: Checkpoint,
    pub justification_bits: BitVector<T::JustificationBitsLength>,
    pub finalized_checkpoint: Checkpoint,
}
