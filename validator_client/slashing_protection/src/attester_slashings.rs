use crate::enums::{NotSafe, Safe, ValidityReason};
use ssz_derive::{Decode, Encode};
use tree_hash::TreeHash;
use types::{AttestationData, AttestationDataAndCustodyBit, Epoch, Hash256};

#[derive(Debug, Clone, Encode, Decode)]
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

    pub fn from(attestation: &AttestationDataAndCustodyBit) -> Self {
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
