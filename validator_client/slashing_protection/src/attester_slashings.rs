use crate::enums::{NotSafe, Safe, ValidityReason};
use rusqlite::{params, Connection};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use std::convert::From;
use std::str::FromStr;
use tree_hash::TreeHash;
use types::{AttestationData, Epoch, Hash256};

#[derive(Debug, Clone, Encode, Decode, PartialEq)]
pub struct SignedAttestation {
    source_epoch: Epoch,
    target_epoch: Epoch,
    signing_root: Hash256,
}

impl SignedAttestation {
    pub fn new(source_epoch: Epoch, target_epoch: Epoch, signing_root: Hash256) -> Self {
        Self {
            source_epoch,
            target_epoch,
            signing_root,
        }
    }
}

impl From<&AttestationData> for SignedAttestation {
    fn from(attestation: &AttestationData) -> Self {
        Self {
            source_epoch: attestation.source.epoch,
            target_epoch: attestation.target.epoch,
            signing_root: Hash256::from_slice(&attestation.tree_hash_root()),
        }
    }
}

#[derive(PartialEq, Debug)]
pub enum InvalidAttestation {
    DoubleVote(SignedAttestation),
    SurroundingVote(SignedAttestation),
    SurroundedVote(SignedAttestation),
}

fn check_surrounded(
    attestation_data: &AttestationData,
    attestation_history: &[SignedAttestation],
) -> Result<(), NotSafe> {
    let surrounded = attestation_history
        .iter()
        .rev()
        .position(|historical_attestation| {
            historical_attestation.source_epoch < attestation_data.source.epoch
        });
    match surrounded {
        Some(index) => Err(NotSafe::InvalidAttestation(
            InvalidAttestation::SurroundedVote(
                attestation_history[attestation_history.len() - 1 - index].clone(),
            ),
        )),
        None => Ok(()),
    }
}

fn check_surrounding(
    attestation_data: &AttestationData,
    attestation_history: &[SignedAttestation],
) -> Result<(), NotSafe> {
    let surrounding = attestation_history
        .iter()
        .rev()
        .position(|historical_attestation| {
            historical_attestation.source_epoch > attestation_data.source.epoch
        });
    match surrounding {
        Some(index) => Err(NotSafe::InvalidAttestation(
            InvalidAttestation::SurroundingVote(
                attestation_history[attestation_history.len() - 1 - index].clone(),
            ),
        )),
        None => Ok(()),
    }
}

/// Checks if the incoming attestation is surrounding a vote, is a surrounded by another vote, or if it is a double vote.
pub fn check_for_attester_slashing(
    attestation_data: &AttestationData,
    conn: &Connection,
) -> Result<Safe, NotSafe> {
    let mut is_empty_stmt = conn.prepare("select exists (select 1 from MyTable)")?;

    if is_empty_stmt.exists(params![])? {
        return Ok(Safe {
            reason: ValidityReason::EmptyHistory,
        });
    }

    // optimize by selecting only what we need?
    let mut attestation_history_select =
        conn.prepare("select slot, signing_root from signed_blocks order by slot asc")?;
    let history = attestation_history_select.query_map(params![], |row| {
        let target_str: String = row.get(0)?;
        let source_str: String = row.get(1)?;
        let hash_blob: Vec<u8> = row.get(2)?;

        Ok(SignedAttestation {
            target_epoch: Epoch::from(
                u64::from_str(target_str.as_ref()).expect("should have a valid u64 stored in db"),
            ),
            source_epoch: Epoch::from(
                u64::from_str(source_str.as_ref()).expect("should have a valid u64 stored in db"),
            ),
            signing_root: Hash256::from_ssz_bytes(hash_blob.as_ref())
                .expect("should have a valid ssz encoded hash256 in db"),
        })
    })?;

    let mut attestation_history = vec![];
    for attestation in history {
        attestation_history.push(attestation.unwrap())
    }

    // Getting the index of the current SignedAttestation that is closest to the incoming attestation
    let target_index = match attestation_history
        .iter()
        .rev()
        .position(|historical_attestation| {
            historical_attestation.target_epoch <= attestation_data.target.epoch
        }) {
        None => return Err(NotSafe::PruningError),
        Some(index) => attestation_history.len() - index - 1,
    };

    if attestation_history[target_index].target_epoch == attestation_data.target.epoch {
        if attestation_history[target_index].signing_root
            == Hash256::from_slice(&attestation_data.tree_hash_root())
        {
            return Ok(Safe {
                reason: ValidityReason::SameVote,
            });
        } else {
            return Err(NotSafe::InvalidAttestation(InvalidAttestation::DoubleVote(
                attestation_history[target_index].clone(),
            )));
        }
    }

    check_surrounded(attestation_data, &attestation_history[target_index + 1..])?;

    // Getting the index of the second closest SignedAttestation that has a source equal to the new attestation's target
    let source_index =
        match attestation_history[..=target_index]
            .iter()
            .rev()
            .position(|historical_attestation| {
                historical_attestation.target_epoch <= attestation_data.source.epoch
            }) {
            None => 0,
            // Adding plus one here to have the second one and not the first one, for a small optimization
            Some(index) => target_index - index + 1,
        };

    check_surrounding(
        attestation_data,
        &attestation_history[source_index..=target_index],
    )?;

    Ok(Safe {
        reason: ValidityReason::Valid,
    })
}

/*#[cfg(test)]
mod attestation_tests {
    use super::*;
    use types::{Checkpoint, Crosslink};

    fn build_checkpoint(epoch_num: u64) -> Checkpoint {
        Checkpoint {
            epoch: Epoch::from(epoch_num),
            root: Hash256::zero(),
        }
    }

    impl SignedAttestation {
        fn new(source_epoch: u64, target_epoch: u64, signing_root: Hash256) -> Self {
            Self {
                source_epoch: Epoch::from(source_epoch),
                target_epoch: Epoch::from(target_epoch),
                signing_root,
            }
        }
    }

    fn attestation_data_builder(source: u64, target: u64) -> AttestationData {
        let source = build_checkpoint(source);
        let target = build_checkpoint(target);
        let crosslink = Crosslink::default();

        AttestationData {
            beacon_block_root: Hash256::zero(),
            source,
            target,
            crosslink,
        }
    }

    #[test]
    fn valid_empty_history() {
        let history = vec![];

        let attestation_data = attestation_data_builder(2, 3);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Ok(Safe {
                reason: ValidityReason::EmptyHistory,
            })
        );
    }

    #[test]
    fn valid_middle_attestation() {
        let mut history = vec![];
        history.push(SignedAttestation::new(0, 1, Hash256::random()));
        history.push(SignedAttestation::new(2, 3, Hash256::random()));

        let attestation_data = attestation_data_builder(1, 2);

        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Ok(Safe {
                reason: ValidityReason::Valid,
            })
        );
    }

    #[test]
    fn valid_last_attestation() {
        let mut history = vec![];
        history.push(SignedAttestation::new(0, 1, Hash256::random()));
        history.push(SignedAttestation::new(1, 2, Hash256::random()));

        let attestation_data = attestation_data_builder(2, 3);

        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Ok(Safe {
                reason: ValidityReason::Valid,
            })
        );
    }

    #[test]
    fn valid_source_from_first_entry() {
        let mut history = vec![];
        history.push(SignedAttestation::new(6, 7, Hash256::random()));

        let attestation_data = attestation_data_builder(6, 8);

        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Ok(Safe {
                reason: ValidityReason::Valid,
            })
        );
    }

    #[test]
    fn invalid_source_from_first_entry() {
        let mut history = vec![];
        history.push(SignedAttestation::new(6, 8, Hash256::random()));

        let attestation_data = attestation_data_builder(6, 7);

        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::PruningError)
        );
    }

    #[test]
    fn valid_same_vote_first() {
        let mut history = vec![];

        let attestation_data = attestation_data_builder(0, 1);

        history.push(SignedAttestation::new(
            0,
            1,
            Hash256::from_slice(&attestation_data.tree_hash_root()),
        ));
        history.push(SignedAttestation::new(1, 2, Hash256::random()));
        history.push(SignedAttestation::new(2, 3, Hash256::random()));

        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Ok(Safe {
                reason: ValidityReason::SameVote,
            })
        );
    }

    #[test]
    fn valid_same_vote_middle() {
        let mut history = vec![];

        let attestation_data = attestation_data_builder(1, 2);

        history.push(SignedAttestation::new(0, 1, Hash256::random()));
        history.push(SignedAttestation::new(
            1,
            2,
            Hash256::from_slice(&attestation_data.tree_hash_root()),
        ));
        history.push(SignedAttestation::new(2, 3, Hash256::random()));

        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Ok(Safe {
                reason: ValidityReason::SameVote,
            })
        );
    }

    #[test]
    fn valid_same_vote_last() {
        let mut history = vec![];

        let attestation_data = attestation_data_builder(2, 3);

        history.push(SignedAttestation::new(0, 1, Hash256::random()));
        history.push(SignedAttestation::new(1, 2, Hash256::random()));
        history.push(SignedAttestation::new(
            2,
            3,
            Hash256::from_slice(&attestation_data.tree_hash_root()),
        ));

        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Ok(Safe {
                reason: ValidityReason::SameVote,
            })
        );
    }

    #[test]
    fn invalid_double_vote_first() {
        let mut history = vec![];
        history.push(SignedAttestation::new(3, 4, Hash256::random()));
        history.push(SignedAttestation::new(4, 5, Hash256::random()));
        history.push(SignedAttestation::new(5, 6, Hash256::random()));

        let attestation_data = attestation_data_builder(3, 4);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(InvalidAttestation::DoubleVote(
                history[0].clone()
            )))
        );
    }

    #[test]
    fn invalid_double_vote_middle() {
        let mut history = vec![];
        history.push(SignedAttestation::new(3, 4, Hash256::random()));
        history.push(SignedAttestation::new(4, 5, Hash256::random()));
        history.push(SignedAttestation::new(5, 6, Hash256::random()));

        let attestation_data = attestation_data_builder(4, 5);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(InvalidAttestation::DoubleVote(
                history[1].clone()
            )))
        );
    }

    #[test]
    fn invalid_double_vote_last() {
        let mut history = vec![];
        history.push(SignedAttestation::new(3, 4, Hash256::random()));
        history.push(SignedAttestation::new(4, 5, Hash256::random()));
        history.push(SignedAttestation::new(5, 6, Hash256::random()));

        let attestation_data = attestation_data_builder(5, 6);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(InvalidAttestation::DoubleVote(
                history[2].clone()
            )))
        );
    }

    #[test]
    fn invalid_double_vote_before() {
        let mut history = vec![];
        history.push(SignedAttestation::new(3, 4, Hash256::random()));
        history.push(SignedAttestation::new(4, 5, Hash256::random()));
        history.push(SignedAttestation::new(5, 6, Hash256::random()));

        let attestation_data = attestation_data_builder(2, 4);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(InvalidAttestation::DoubleVote(
                history[0].clone()
            )))
        );
    }

    #[test]
    fn invalid_surround_first() {
        let mut history = vec![];
        history.push(SignedAttestation::new(2, 3, Hash256::random()));
        history.push(SignedAttestation::new(4, 5, Hash256::random()));
        history.push(SignedAttestation::new(6, 7, Hash256::random()));

        let attestation_data = attestation_data_builder(1, 4);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundingVote(history[0].clone())
            ))
        );
    }

    #[test]
    fn invalid_surround_middle() {
        let mut history = vec![];
        history.push(SignedAttestation::new(2, 3, Hash256::random()));
        history.push(SignedAttestation::new(4, 5, Hash256::random()));
        history.push(SignedAttestation::new(6, 7, Hash256::random()));

        let attestation_data = attestation_data_builder(3, 6);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundingVote(history[1].clone())
            ))
        );
    }

    #[test]
    fn invalid_surround_last() {
        let mut history = vec![];
        history.push(SignedAttestation::new(2, 3, Hash256::random()));
        history.push(SignedAttestation::new(4, 5, Hash256::random()));
        history.push(SignedAttestation::new(6, 7, Hash256::random()));

        let attestation_data = attestation_data_builder(5, 8);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundingVote(history[2].clone())
            ))
        );
    }

    #[test]
    fn invalid_surround_before() {
        let mut history = vec![];
        history.push(SignedAttestation::new(221, 224, Hash256::random()));

        let attestation_data = attestation_data_builder(4, 227);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundingVote(history[0].clone())
            ))
        );
    }

    #[test]
    fn invalid_surround_from_first_source() {
        let mut history = vec![];
        history.push(SignedAttestation::new(2, 3, Hash256::random()));
        history.push(SignedAttestation::new(3, 4, Hash256::random()));

        let attestation_data = attestation_data_builder(2, 5);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundingVote(history[1].clone())
            ))
        );
    }

    #[test]
    fn invalid_surround_multiple_votes() {
        let mut history = vec![];
        history.push(SignedAttestation::new(0, 1, Hash256::random()));
        history.push(SignedAttestation::new(1, 2, Hash256::random()));
        history.push(SignedAttestation::new(2, 3, Hash256::random()));
        history.push(SignedAttestation::new(3, 4, Hash256::random()));

        let attestation_data = attestation_data_builder(1, 5);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundingVote(history[3].clone())
            ))
        );
    }

    #[test]
    fn invalid_surrounded_first_vote() {
        let mut history = vec![];
        history.push(SignedAttestation::new(0, 1, Hash256::random()));
        history.push(SignedAttestation::new(0, 7, Hash256::random()));

        let attestation_data = attestation_data_builder(1, 2);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundedVote(history[1].clone())
            ))
        );
    }

    #[test]
    fn invalid_surrounded_middle_vote() {
        let mut history = vec![];
        history.push(SignedAttestation::new(1, 2, Hash256::random()));
        history.push(SignedAttestation::new(1, 6, Hash256::random()));
        history.push(SignedAttestation::new(6, 7, Hash256::random()));

        let attestation_data = attestation_data_builder(2, 3);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundedVote(history[1].clone())
            ))
        );
    }

    #[test]
    fn invalid_surrounded_last_vote() {
        let mut history = vec![];
        history.push(SignedAttestation::new(1, 2, Hash256::random()));
        history.push(SignedAttestation::new(1, 6, Hash256::random()));

        let attestation_data = attestation_data_builder(2, 3);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundedVote(history[1].clone())
            ))
        );
    }

    #[test]
    fn invalid_surrounded_multiple_votes() {
        let mut history = vec![];
        history.push(SignedAttestation::new(0, 1, Hash256::random()));
        history.push(SignedAttestation::new(1, 5, Hash256::random()));
        history.push(SignedAttestation::new(2, 6, Hash256::random()));

        let attestation_data = attestation_data_builder(3, 4);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundedVote(history[2].clone())
            ))
        );
    }

    #[test]
    fn invalid_prunning_error_target_too_small() {
        let mut history = vec![];
        history.push(SignedAttestation::new(221, 224, Hash256::random()));

        let attestation_data = attestation_data_builder(4, 5);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::PruningError)
        );
    }

    #[test]
    fn invalid_prunning_error_target_surrounded() {
        let mut history = vec![];
        history.push(SignedAttestation::new(221, 224, Hash256::random()));

        let attestation_data = attestation_data_builder(222, 223);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::PruningError)
        );
    }
}
*/
