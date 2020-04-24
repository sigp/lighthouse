use crate::validator_history::ValidatorHistory;
use crate::{NotSafe, Safe, ValidityReason};
use rusqlite::params;
use types::{BeaconBlockHeader, Hash256, Slot};

#[derive(PartialEq, Debug)]
pub enum InvalidBlock {
    DoubleBlockProposal(SignedBlock),
}

#[derive(Clone, Debug, PartialEq)]
pub struct SignedBlock {
    pub slot: Slot,
    signing_root: Hash256,
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

impl ValidatorHistory<SignedBlock> {
    pub fn check_for_proposer_slashing(
        &self,
        block_header: &BeaconBlockHeader,
    ) -> Result<Safe, NotSafe> {
        let conn = self.conn_pool.get()?;

        // Checking if history is empty
        let mut empty_select = conn.prepare("SELECT 1 FROM signed_blocks LIMIT 1")?;
        if !empty_select.exists(params![])? {
            return Ok(Safe {
                reason: ValidityReason::EmptyHistory,
            });
        }

        // Short-circuit: checking if the incoming block has a higher slot than the maximum slot
        // in the DB.
        let mut latest_block_select =
            conn.prepare("SELECT MAX(slot), signing_root FROM signed_blocks")?;
        let latest_block = latest_block_select.query_row(params![], |row| {
            let slot = row.get(0)?;
            let signing_bytes: Vec<u8> = row.get(1)?;
            let signing_root = Hash256::from_slice(&signing_bytes);
            Ok(SignedBlock::new(slot, signing_root))
        })?;

        if block_header.slot > latest_block.slot {
            return Ok(Safe {
                reason: ValidityReason::Valid,
            });
        }

        // Checking for Pruning Error i.e the incoming block slot is smaller than the minimum slot
        // signed in the DB.
        let mut min_select = conn.prepare("SELECT MIN(slot) FROM signed_blocks")?;
        let oldest_slot: Slot = min_select.query_row(params![], |row| row.get(0))?;
        if block_header.slot < oldest_slot {
            // FIXME(slashing): consider renaming
            return Err(NotSafe::PruningError);
        }

        // Checking if there's an existing entry in the db that has a slot equal to the
        // block_header's slot.
        let mut same_slot_select =
            conn.prepare("SELECT slot, signing_root FROM signed_blocks WHERE slot = ?")?;
        let same_slot_query = same_slot_select.query_row(params![block_header.slot], |row| {
            let slot = row.get(0)?;
            let signing_bytes: Vec<u8> = row.get(1)?;
            let signing_root = Hash256::from_slice(&signing_bytes);
            Ok(SignedBlock::new(slot, signing_root))
        });

        // FIXME(slashing): differentiate DB error and empty result
        if let Ok(same_slot_attest) = same_slot_query {
            if same_slot_attest.signing_root == block_header.canonical_root() {
                // Same slot and same hash -> we're re-broadcasting a previously signed block
                Ok(Safe {
                    reason: ValidityReason::SameData,
                })
            } else {
                // Same epoch but not the same hash -> it's a DoubleBlockProposal
                Err(NotSafe::InvalidBlock(InvalidBlock::DoubleBlockProposal(
                    same_slot_attest,
                )))
            }
        } else {
            Ok(Safe {
                reason: ValidityReason::Valid,
            })
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
