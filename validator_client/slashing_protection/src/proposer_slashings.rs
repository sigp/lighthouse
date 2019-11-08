use crate::enums::{NotSafe, Safe, ValidityReason};
use rusqlite::{params, Connection};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use std::convert::From;
use std::str::FromStr;
use types::{BeaconBlockHeader, Hash256, Slot};

#[derive(PartialEq, Debug)]
pub enum InvalidBlock {
    BlockSlotTooEarly(SignedBlock),
    DoubleBlockProposal(SignedBlock),
}

#[derive(Debug, Clone, Encode, Decode, PartialEq)]
pub struct SignedBlock {
    slot: Slot,
    signing_root: Hash256,
}

impl SignedBlock {
    pub fn new(slot: Slot, signing_root: Hash256) -> Self {
        Self { slot, signing_root }
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

pub fn check_for_proposer_slashing(
    block_header: &BeaconBlockHeader,
    conn: &Connection,
) -> Result<Safe, NotSafe> {
    let mut is_empty_stmt = conn.prepare("select exists (select 1 from MyTable)")?;

    if is_empty_stmt.exists(params![])? {
        return Ok(Safe {
            reason: ValidityReason::EmptyHistory,
        });
    }

    // optimize by selecting only what we need?
    let mut block_history_select =
        conn.prepare("select slot, signing_root from signed_blocks order by slot asc")?;
    let history = block_history_select.query_map(params![], |row| {
        let slot_str: String = row.get(0)?;
        let hash_blob: Vec<u8> = row.get(1)?;
        Ok(SignedBlock {
            slot: Slot::from(
                u64::from_str(slot_str.as_ref()).expect("should have a valid u64 stored in db"),
            ),
            signing_root: Hash256::from_ssz_bytes(hash_blob.as_ref())
                .expect("should have a valid ssz encoded hash256 in db"),
        })
    })?;

    let mut block_history = vec![];
    for block in history {
        block_history.push(block.unwrap())
    }

    let latest_signed_block = &block_history[block_history.len() - 1];
    if block_header.slot > latest_signed_block.slot {
        return Ok(Safe {
            reason: ValidityReason::Valid,
        });
    }

    let index = block_history
        .iter()
        .rev()
        .position(|historical_block| historical_block.slot <= block_header.slot);

    let index = match index {
        None => return Err(NotSafe::PruningError),
        Some(num) => block_history.len() - 1 - num,
    };

    if block_history[index].slot == block_header.slot {
        if block_history[index].signing_root == block_header.canonical_root() {
            Ok(Safe {
                reason: ValidityReason::SameVote,
            })
        } else {
            Err(NotSafe::InvalidBlock(InvalidBlock::DoubleBlockProposal(
                block_history[index].clone(),
            )))
        }
    } else {
        Err(NotSafe::InvalidBlock(InvalidBlock::BlockSlotTooEarly(
            block_history[block_history.len() - 1].clone(),
        )))
    }
}

/*#[cfg(test)]
mod block_tests {
    use super::*;
    use types::{BeaconBlockHeader, Signature};

    impl SignedBlock {
        fn new(slot: u64, signing_root: Hash256) -> Self {
            Self {
                slot: Slot::from(slot),
                signing_root,
            }
        }
    }

    fn block_builder(slot: u64) -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot: Slot::from(slot),
            parent_root: Hash256::random(),
            state_root: Hash256::random(),
            body_root: Hash256::random(),
            signature: Signature::empty_signature(),
        }
    }

    #[test]
    fn valid_empty_history() {
        let history = vec![];

        let new_block = block_builder(3);

        assert_eq!(
            check_for_proposer_slashing(&new_block, &history),
            Ok(Safe {
                reason: ValidityReason::EmptyHistory
            })
        );
    }

    #[test]
    fn valid_block() {
        let mut history = vec![];

        history.push(SignedBlock::new(1, Hash256::random()));
        history.push(SignedBlock::new(2, Hash256::random()));
        let new_block = block_builder(3);

        assert_eq!(
            check_for_proposer_slashing(&new_block, &history),
            Ok(Safe {
                reason: ValidityReason::Valid
            })
        );
    }

    #[test]
    fn valid_same_block() {
        let mut history = vec![];

        let new_block = block_builder(3);

        history.push(SignedBlock::new(1, Hash256::random()));
        history.push(SignedBlock::new(2, Hash256::random()));
        history.push(SignedBlock::new(3, new_block.canonical_root()));

        assert_eq!(
            check_for_proposer_slashing(&new_block, &history),
            Ok(Safe {
                reason: ValidityReason::SameVote
            })
        );
    }

    #[test]
    fn invalid_pruning_error() {
        let mut history = vec![];

        let new_block = block_builder(0);

        history.push(SignedBlock::new(2, Hash256::random()));
        history.push(SignedBlock::new(3, Hash256::random()));

        assert_eq!(
            check_for_proposer_slashing(&new_block, &history),
            Err(NotSafe::PruningError)
        );
    }

    #[test]
    fn invalid_slot_too_early() {
        let mut history = vec![];

        history.push(SignedBlock::new(1, Hash256::random()));
        history.push(SignedBlock::new(3, Hash256::random()));

        let new_block = block_builder(2);

        assert_eq!(
            check_for_proposer_slashing(&new_block, &history),
            Err(NotSafe::InvalidBlock(InvalidBlock::BlockSlotTooEarly(
                history[1].clone()
            )))
        );
    }

    #[test]
    fn invalid_double_block_proposal() {
        let mut history = vec![];

        history.push(SignedBlock::new(1, Hash256::random()));
        history.push(SignedBlock::new(2, Hash256::random()));
        history.push(SignedBlock::new(3, Hash256::random()));

        let new_block = block_builder(2);

        assert_eq!(
            check_for_proposer_slashing(&new_block, &history),
            Err(NotSafe::InvalidBlock(InvalidBlock::DoubleBlockProposal(
                history[1].clone()
            )))
        );
    }
}
*/
