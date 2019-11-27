use crate::utils::{i64_to_u64, u64_to_i64};
use crate::validator_history::ValidatorHistory;
use crate::{NotSafe, Safe, ValidityReason};
use rusqlite::params;
use std::convert::From;
use types::{BeaconBlockHeader, Epoch, Hash256};

#[derive(PartialEq, Debug)]
pub enum InvalidBlock {
    BlockSlotTooEarly(SignedBlock),
    DoubleBlockProposal(SignedBlock),
}

#[derive(Clone, Debug, PartialEq)]
pub struct SignedBlock {
    pub epoch: Epoch,
    signing_root: Hash256,
}

impl SignedBlock {
    pub fn new(epoch: u64, signing_root: Hash256) -> Self {
        Self {
            epoch: Epoch::from(epoch),
            signing_root,
        }
    }

    pub fn from(header: &BeaconBlockHeader, slots_per_epoch: u64) -> Self {
        Self {
            epoch: header.slot.epoch(slots_per_epoch),
            signing_root: header.canonical_root(),
        }
    }
}

impl ValidatorHistory<SignedBlock> {
    pub fn check_for_proposer_slashing(
        &self,
        block_header: &BeaconBlockHeader,
    ) -> Result<Safe, NotSafe> {
        let conn = self.conn_pool.get()?;

        // Checking if history is empty
        let mut empty_select = conn.prepare("select 1 from signed_blocks limit 1")?;
        if !empty_select.exists(params![])? {
            return Ok(Safe {
                reason: ValidityReason::EmptyHistory,
            });
        }

        let slots_per_epoch = self.slots_per_epoch()?;

        // Short-circuit: checking if the incoming block has a higher epoch than the maximum epoch in the db.
        let mut latest_block_select =
            conn.prepare("select max(epoch), signing_root from signed_blocks")?;
        let latest_block = latest_block_select.query_row(params![], |row| {
            let i64_epoch: i64 = row.get(0)?;
            let u64_epoch = i64_to_u64(i64_epoch);
            let signing_bytes: Vec<u8> = row.get(1)?;
            let signing_root = Hash256::from_slice(signing_bytes.as_ref());
            Ok(SignedBlock::new(u64_epoch, signing_root))
        })?;

        let header_epoch = block_header.slot.epoch(slots_per_epoch);
        if header_epoch > latest_block.epoch {
            return Ok(Safe {
                reason: ValidityReason::Valid,
            });
        }

        // Checking for Pruning Error i.e the incoming block epoch is smaller than the minimum epoch signed in the db.
        let mut min_select = conn.prepare("select min(epoch) from signed_blocks")?;
        let oldest_epoch = min_select.query_row(params![], |row| {
            let i64_epoch: i64 = row.get(0)?;
            let u64_epoch = i64_to_u64(i64_epoch);
            Ok(u64_epoch)
        })?;
        if header_epoch < oldest_epoch {
            return Err(NotSafe::PruningError);
        }

        // Checking if there's an existing entry in the db that has an epoch equal to the block_header's epoch.
        let mut same_epoch_select =
            conn.prepare("select epoch, signing_root from signed_blocks where epoch = ?")?;
        let block_header_epoch = u64_to_i64(header_epoch.into());
        let same_epoch_query = same_epoch_select.query_row(params![block_header_epoch], |row| {
            let i64_epoch: i64 = row.get(0)?;
            let u64_epoch = i64_to_u64(i64_epoch);
            let signing_bytes: Vec<u8> = row.get(1)?;
            let signing_root = Hash256::from_slice(&signing_bytes[..]);
            Ok(SignedBlock::new(u64_epoch, signing_root))
        });

        if let Ok(same_epoch_attest) = same_epoch_query {
            if same_epoch_attest.signing_root == block_header.canonical_root() {
                // Same epoch and same hash -> we're re-broadcasting a previously signed block
                Ok(Safe {
                    reason: ValidityReason::SameVote,
                })
            } else {
                // Same epoch but not the same hash -> it's a DoubleBlockProposal
                Err(NotSafe::InvalidBlock(InvalidBlock::DoubleBlockProposal(
                    same_epoch_attest,
                )))
            }
        } else {
            // No signed block with the same epoch -> the incoming block is targeting an invalid epoch
            Err(NotSafe::InvalidBlock(InvalidBlock::BlockSlotTooEarly(
                latest_block,
            )))
        }
    }
}

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
            ValidatorHistory::empty(filename, Some(slots_per_epoch)).expect("IO error with file");

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
    fn invalid_slot_too_early() {
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
        let slots_per_epoch = block_history
            .slots_per_epoch()
            .expect("should have slots_per_epoch");
        assert_eq!(
            res,
            Err(NotSafe::InvalidBlock(InvalidBlock::BlockSlotTooEarly(
                SignedBlock::from(&second, slots_per_epoch)
            )))
        );
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

        let new_block = block_builder(2 * slots_per_epoch);
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
