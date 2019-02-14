use crate::{EpochProcessable, EpochProcessingError};
use types::{beacon_state::CommitteesError, BeaconState, ChainSpec, Hash256};

#[derive(Debug, PartialEq)]
pub enum Error {
    CommitteesError(CommitteesError),
    EpochProcessingError(EpochProcessingError),
}

pub trait SlotProcessable {
    fn per_slot_processing(
        &mut self,
        previous_block_root: Hash256,
        spec: &ChainSpec,
    ) -> Result<(), Error>;
}

impl SlotProcessable for BeaconState
where
    BeaconState: EpochProcessable,
{
    fn per_slot_processing(
        &mut self,
        previous_block_root: Hash256,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        if (self.slot + 1) % spec.epoch_length == 0 {
            self.per_epoch_processing(spec)?;
        }

        self.slot += 1;

        self.latest_randao_mixes[self.slot.as_usize() % spec.latest_randao_mixes_length] =
            self.latest_randao_mixes[(self.slot.as_usize() - 1) % spec.latest_randao_mixes_length];

        // Block roots.
        self.latest_block_roots[(self.slot.as_usize() - 1) % spec.latest_block_roots_length] =
            previous_block_root;

        if self.slot.as_usize() % spec.latest_block_roots_length == 0 {
            let root = merkle_root(&self.latest_block_roots[..]);
            self.batched_block_roots.push(root);
        }
        Ok(())
    }
}

fn merkle_root(_input: &[Hash256]) -> Hash256 {
    Hash256::zero()
}

impl From<CommitteesError> for Error {
    fn from(e: CommitteesError) -> Error {
        Error::CommitteesError(e)
    }
}

impl From<EpochProcessingError> for Error {
    fn from(e: EpochProcessingError) -> Error {
        Error::EpochProcessingError(e)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
