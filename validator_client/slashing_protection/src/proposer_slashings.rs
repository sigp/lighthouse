use crate::enums::{NotSafe, Safe, ValidityReason};
use crate::slashing_protection::HistoryInfo;
use crate::utils::{i64_to_u64, u64_to_i64};
use rusqlite::params;
use std::convert::From;
use types::{BeaconBlockHeader, Hash256, Slot};

#[derive(PartialEq, Debug)]
pub enum InvalidBlock {
    BlockSlotTooEarly(SignedBlock),
    DoubleBlockProposal(SignedBlock),
}

#[derive(Clone, Debug, PartialEq)]
pub struct SignedBlock {
    pub slot: Slot,
    signing_root: Hash256,
}

impl SignedBlock {
    pub fn new(slot: u64, signing_root: Hash256) -> Self {
        Self {
            slot: Slot::from(slot),
            signing_root,
        }
    }
}

impl From<&BeaconBlockHeader> for SignedBlock {
    fn from(header: &BeaconBlockHeader) -> Self {
        Self {
            slot: header.slot,
            signing_root: header.canonical_root(),
        }
    }
}

impl HistoryInfo<SignedBlock> {
    pub fn check_for_proposer_slashing(
        &self,
        block_header: &BeaconBlockHeader,
    ) -> Result<Safe, NotSafe> {
        // Checking if history is empty
        let mut empty_select = self.conn.prepare("select 1 from signed_blocks limit 1")?;
        if !empty_select.exists(params![])? {
            return Ok(Safe {
                reason: ValidityReason::EmptyHistory,
            });
        }

        // Short-circuit: checking if the incoming block has a higher slot than the maximum slot in the db.
        let mut latest_block_select = self
            .conn
            .prepare("select max(slot), signing_root from signed_blocks")?;
        let latest_block = latest_block_select.query_row(params![], |row| {
            let i64_slot: i64 = row.get(0)?;
            let u64_slot = i64_to_u64(i64_slot);
            let signing_bytes: Vec<u8> = row.get(1)?;
            let signing_root = Hash256::from_slice(signing_bytes.as_ref());
            Ok(SignedBlock::new(u64_slot, signing_root))
        })?;
        if block_header.slot > latest_block.slot {
            return Ok(Safe {
                reason: ValidityReason::Valid,
            });
        }

        // Checking for Pruning Error i.e the incoming block slot is smaller than the minimum slot signed in the db.
        let mut min_select = self.conn.prepare("select min(slot) from signed_blocks")?;
        let oldest_slot = min_select.query_row(params![], |row| {
            let i64_slot: i64 = row.get(0)?;
            let u64_slot = i64_to_u64(i64_slot);
            Ok(u64_slot)
        })?;
        if block_header.slot < Slot::from(oldest_slot) {
            return Err(NotSafe::PruningError);
        }

        // Checking if there's an existing entry in the db that has a slot equal to the block_header's slot.
        let mut same_slot_select = self
            .conn
            .prepare("select slot, signing_root from signed_blocks where slot = ?")?;
        let block_header_slot = u64_to_i64(block_header.slot.into());
        let same_slot_query = same_slot_select.query_row(params![block_header_slot], |row| {
            let i64_slot: i64 = row.get(0)?;
            let u64_slot = i64_to_u64(i64_slot);
            let signing_bytes: Vec<u8> = row.get(1)?;
            let signing_root = Hash256::from_slice(&signing_bytes[..]);
            Ok(SignedBlock::new(u64_slot, signing_root))
        });

        if let Ok(same_slot_attest) = same_slot_query {
            if same_slot_attest.signing_root == block_header.canonical_root() {
                // Same slot and same hash -> we're re-broadcasting a previously signed block
                Ok(Safe {
                    reason: ValidityReason::SameVote,
                })
            } else {
                // Same slot but not the same hash -> it's a DoubleBlockProposal
                Err(NotSafe::InvalidBlock(InvalidBlock::DoubleBlockProposal(
                    same_slot_attest,
                )))
            }
        } else {
            // No signed block with the same slot -> the incoming block is targeting an invalid slot
            Err(NotSafe::InvalidBlock(InvalidBlock::BlockSlotTooEarly(
                latest_block,
            )))
        }
    }
}

#[cfg(test)]
mod block_tests {
    use super::*;
    use crate::slashing_protection::SlashingProtection;
    use tempfile::NamedTempFile;
    use types::{BeaconBlockHeader, Signature};

    fn block_builder(slot: u64) -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot: Slot::from(slot),
            parent_root: Hash256::random(),
            state_root: Hash256::random(),
            body_root: Hash256::random(),
            signature: Signature::empty_signature(),
        }
    }

    fn create_tmp() -> (HistoryInfo<SignedBlock>, NamedTempFile) {
        let block_file = NamedTempFile::new().expect("couldn't create temporary file");
        let filename = block_file.path();

        let block_history: HistoryInfo<SignedBlock> =
            HistoryInfo::empty(filename).expect("IO error with file");

        (block_history, block_file)
    }

    #[test]
    fn valid_empty_history() {
        let (mut block_history, _attestation_file) = create_tmp();

        let new_block = block_builder(3);
        let res = block_history.update_if_valid(&new_block);
        assert_eq!(res, Ok(()));
    }

    #[test]
    fn valid_block() {
        let (mut block_history, _attestation_file) = create_tmp();

        let first = block_builder(1);
        block_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");
        let second = block_builder(2);
        block_history
            .update_if_valid(&second)
            .expect("should have inserted prev data");

        let new_block = block_builder(3);
        let res = block_history.update_if_valid(&new_block);
        assert_eq!(res, Ok(()));
    }

    #[test]
    fn valid_same_block() {
        let (mut block_history, _attestation_file) = create_tmp();

        let first = block_builder(1);
        block_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");
        let second = block_builder(2);
        block_history
            .update_if_valid(&second)
            .expect("should have inserted prev data");

        let res = block_history.update_if_valid(&second);
        assert_eq!(res, Ok(()));
    }

    #[test]
    fn invalid_pruning_error() {
        let (mut block_history, _attestation_file) = create_tmp();

        let first = block_builder(1);
        block_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");
        let second = block_builder(2);
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

        let first = block_builder(1);
        block_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");
        let second = block_builder(3);
        block_history
            .update_if_valid(&second)
            .expect("should have inserted prev data");

        let new_block = block_builder(2);
        let res = block_history.update_if_valid(&new_block);
        assert_eq!(
            res,
            Err(NotSafe::InvalidBlock(InvalidBlock::BlockSlotTooEarly(
                SignedBlock::from(&second)
            )))
        );
    }

    #[test]
    fn invalid_double_block_proposal() {
        let (mut block_history, _attestation_file) = create_tmp();

        let first = block_builder(1);
        block_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");
        let second = block_builder(2);
        block_history
            .update_if_valid(&second)
            .expect("should have inserted prev data");
        let third = block_builder(3);
        block_history
            .update_if_valid(&third)
            .expect("should have inserted prev data");

        let new_block = block_builder(2);
        let res = block_history.update_if_valid(&new_block);
        assert_eq!(
            res,
            Err(NotSafe::InvalidBlock(InvalidBlock::DoubleBlockProposal(
                SignedBlock::from(&second)
            )))
        );
    }
}
