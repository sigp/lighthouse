use types::{BeaconBlockHeader, Hash256, Slot};

#[derive(PartialEq, Debug)]
pub enum InvalidBlock {
    DoubleBlockProposal(SignedBlock),
}

#[derive(Clone, Debug, PartialEq)]
pub struct SignedBlock {
    pub slot: Slot,
    pub signing_root: Hash256,
}

impl SignedBlock {
    pub fn new(slot: Slot, signing_root: Hash256) -> Self {
        Self { slot, signing_root }
    }

    pub fn from(header: &BeaconBlockHeader) -> Self {
        // FIXME(slashing): use real signing_root
        Self {
            slot: header.slot,
            signing_root: header.canonical_root(),
        }
    }
}

// FIXME(slashing): fix these tests
#[cfg(test)]
mod block_tests {
    use super::*;
    use crate::validator_history::SlashingProtection;
    use tempfile::NamedTempFile;
    use types::{BeaconBlockHeader, EthSpec, MinimalEthSpec, Signature, Slot};

    fn block_builder(slot: u64) -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot: Slot::from(slot),
            parent_root: Hash256::random(),
            state_root: Hash256::random(),
            body_root: Hash256::random(),
            signature: Signature::empty_signature(),
        }
    }

    fn create_tmp() -> (ValidatorHistory<SignedBlock>, NamedTempFile) {
        let block_file = NamedTempFile::new().expect("couldn't create temporary file");
        let filename = block_file.path();
        let slots_per_epoch = MinimalEthSpec::slots_per_epoch();

        let block_history: ValidatorHistory<SignedBlock> =
            ValidatorHistory::new(filename, Some(slots_per_epoch)).expect("IO error with file");

        (block_history, block_file)
    }

    #[test]
    fn valid_empty_history() {
        let (mut block_history, _attestation_file) = create_tmp();
        let slots_per_epoch = MinimalEthSpec::slots_per_epoch();

        let new_block = block_builder(3 * slots_per_epoch);
        let res = block_history.update_if_valid(&new_block);
        assert_eq!(res, Ok(()));
    }

    #[test]
    fn valid_block() {
        let (mut block_history, _attestation_file) = create_tmp();
        let slots_per_epoch = MinimalEthSpec::slots_per_epoch();

        let first = block_builder(slots_per_epoch);
        block_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");
        let second = block_builder(2 * slots_per_epoch);
        block_history
            .update_if_valid(&second)
            .expect("should have inserted prev data");

        let new_block = block_builder(3 * slots_per_epoch);
        let res = block_history.update_if_valid(&new_block);
        assert_eq!(res, Ok(()));
    }

    #[test]
    fn valid_same_block() {
        let (mut block_history, _attestation_file) = create_tmp();
        let slots_per_epoch = MinimalEthSpec::slots_per_epoch();

        let first = block_builder(slots_per_epoch);
        block_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");
        let second = block_builder(2 * slots_per_epoch);
        block_history
            .update_if_valid(&second)
            .expect("should have inserted prev data");

        let res = block_history.update_if_valid(&second);
        assert_eq!(res, Ok(()));
    }

    #[test]
    fn invalid_pruning_error() {
        let (mut block_history, _attestation_file) = create_tmp();
        let slots_per_epoch = MinimalEthSpec::slots_per_epoch();

        let first = block_builder(slots_per_epoch);
        block_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");
        let second = block_builder(2 * slots_per_epoch);
        block_history
            .update_if_valid(&second)
            .expect("should have inserted prev data");

        let new_block = block_builder(0);
        let res = block_history.update_if_valid(&new_block);
        assert_eq!(res, Err(NotSafe::PruningError));
    }

    #[test]
    fn valid_block_in_the_middle() {
        let (mut block_history, _attestation_file) = create_tmp();
        let slots_per_epoch = MinimalEthSpec::slots_per_epoch();

        let first = block_builder(slots_per_epoch);
        block_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");
        let second = block_builder(3 * slots_per_epoch);
        block_history
            .update_if_valid(&second)
            .expect("should have inserted prev data");

        let new_block = block_builder(2 * slots_per_epoch);
        let res = block_history.update_if_valid(&new_block);
        assert_eq!(res, Ok(()));
    }

    #[test]
    fn invalid_double_block_proposal() {
        let (mut block_history, _attestation_file) = create_tmp();
        let slots_per_epoch = MinimalEthSpec::slots_per_epoch();

        let first = block_builder(slots_per_epoch);
        block_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");
        let second = block_builder(2 * slots_per_epoch);
        block_history
            .update_if_valid(&second)
            .expect("should have inserted prev data");
        let third = block_builder(3 * slots_per_epoch);
        block_history
            .update_if_valid(&third)
            .expect("should have inserted prev data");

        let new_block = block_builder(2 * slots_per_epoch + 2);
        let res = block_history.update_if_valid(&new_block);
        let slots_per_epoch = block_history
            .slots_per_epoch()
            .expect("should have slots_per_epoch");
        assert_eq!(
            res,
            Err(NotSafe::InvalidBlock(InvalidBlock::DoubleBlockProposal(
                SignedBlock::from(&second, slots_per_epoch)
            )))
        );
    }
}
