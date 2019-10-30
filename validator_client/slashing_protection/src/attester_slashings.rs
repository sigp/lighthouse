use crate::enums::{NotSafe, Safe, ValidityReason};
use ssz_derive::{Decode, Encode};
use std::convert::From;
use tree_hash::TreeHash;
use types::{AttestationData, AttestationDataAndCustodyBit, Epoch, Hash256};

#[derive(Debug, Clone, Encode, Decode, PartialEq)]
pub struct SignedAttestation {
    pub source_epoch: Epoch,
    pub target_epoch: Epoch,
    pub signing_root: Hash256,
}

impl SignedAttestation {
    pub fn new(source_epoch: u64, target_epoch: u64, signing_root: Hash256) -> Self {
        Self {
            source_epoch: Epoch::from(source_epoch),
            target_epoch: Epoch::from(target_epoch),
            signing_root,
        }
    }
}

impl From<&AttestationDataAndCustodyBit> for SignedAttestation {
    fn from(attestation: &AttestationDataAndCustodyBit) -> Self {
        Self {
            source_epoch: attestation.data.source.epoch,
            target_epoch: attestation.data.target.epoch,
            signing_root: Hash256::from_slice(&attestation.tree_hash_root()),
        }
    }
}

#[derive(PartialEq, Debug)]
pub enum InvalidAttestation {
    DoubleVote,
    SurroundingVote,
    SurroundedVote,
}

fn check_surrounded(
    attestation_data: &AttestationData,
    attestation_history: &[SignedAttestation],
) -> Result<(), NotSafe> {
    let surrounded = attestation_history.iter().any(|historical_attestation| {
        historical_attestation.source_epoch < attestation_data.source.epoch
    });
    if surrounded {
        Err(NotSafe::InvalidAttestation(
            InvalidAttestation::SurroundedVote,
        ))
    } else {
        Ok(())
    }
}

fn check_surrounding(
    attestation_data: &AttestationData,
    attestation_history: &[SignedAttestation],
) -> Result<(), NotSafe> {
    let surrounding = attestation_history.iter().any(|historical_attestation| {
        historical_attestation.source_epoch > attestation_data.source.epoch
    });
    if surrounding {
        Err(NotSafe::InvalidAttestation(
            InvalidAttestation::SurroundingVote,
        ))
    } else {
        Ok(())
    }
}

pub fn check_for_attester_slashing(
    attestation_data_and_custody: &AttestationDataAndCustodyBit,
    attestation_history: &[SignedAttestation],
) -> Result<Safe, NotSafe> {
    if attestation_history.is_empty() {
        return Ok(Safe {
            insert_index: 0,
            reason: ValidityReason::EmptyHistory,
        });
    }

    let attestation_data = &attestation_data_and_custody.data;
    let target_index = match attestation_history
        .iter()
        .rev()
        .position(|historical_attestation| {
            historical_attestation.target_epoch <= attestation_data.target.epoch
        }) {
        None => return Err(NotSafe::PruningError),
        Some(index) => attestation_history.len() - index - 1,
    };

    check_surrounded(attestation_data, &attestation_history[target_index + 1..])?;
    if attestation_history[target_index].target_epoch == attestation_data.target.epoch {
        if attestation_history[target_index].signing_root
            == Hash256::from_slice(&attestation_data_and_custody.tree_hash_root())
        {
            return Ok(Safe {
                insert_index: target_index,
                reason: ValidityReason::SameVote,
            });
        } else {
            return Err(NotSafe::InvalidAttestation(InvalidAttestation::DoubleVote));
        }
    }

    let source_index =
        match attestation_history[..=target_index]
            .iter()
            .rev()
            .position(|historical_attestation| {
                historical_attestation.target_epoch <= attestation_data.source.epoch
            }) {
            None => 0,
            Some(index) => target_index - index + 1,
        };

    check_surrounding(
        attestation_data,
        &attestation_history[source_index..=target_index],
    )?;

    Ok(Safe {
        insert_index: target_index + 1,
        reason: ValidityReason::Valid,
    })
}

#[cfg(test)]
mod block_tests {
    use crate::enums::*; // SCOTT
    use crate::proposer_slashings::*; // SCOTT
    use types::{BeaconBlockHeader, Hash256, Signature, Slot};

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
                insert_index: 0,
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
                insert_index: 2,
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
                insert_index: 2,
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
    fn invalid_double_block_proposal() {
        let mut history = vec![];

        history.push(SignedBlock::new(1, Hash256::random()));
        history.push(SignedBlock::new(2, Hash256::random()));
        history.push(SignedBlock::new(3, Hash256::random()));

        let new_block = block_builder(2);

        assert_eq!(
            check_for_proposer_slashing(&new_block, &history),
            Err(NotSafe::InvalidBlock(InvalidBlock::DoubleBlockProposal))
        );
    }
}
