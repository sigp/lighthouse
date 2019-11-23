use crate::enums::{NotSafe, Safe, ValidityReason};
use crate::slashing_protection::ValidatorHistory;
use crate::utils::{i64_to_u64, u64_to_i64};
use rusqlite::params;
use std::convert::From;
use tree_hash::TreeHash;
use types::{AttestationData, Epoch, Hash256};

#[derive(Clone, Debug, PartialEq)]
pub struct SignedAttestation {
    source_epoch: Epoch,
    pub target_epoch: Epoch,
    signing_root: Hash256,
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
        .position(|historical_attestation| {
            historical_attestation.source_epoch < attestation_data.source.epoch
        });
    match surrounded {
        Some(index) => Err(NotSafe::InvalidAttestation(
            InvalidAttestation::SurroundedVote(attestation_history[index].clone()),
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
        .position(|historical_attestation| {
            historical_attestation.source_epoch > attestation_data.source.epoch
        });
    match surrounding {
        Some(index) => Err(NotSafe::InvalidAttestation(
            InvalidAttestation::SurroundingVote(attestation_history[index].clone()),
        )),
        None => Ok(()),
    }
}

/// Checks if the incoming attestation is surrounding a vote, is a surrounded by another vote, or if it is a double vote.
impl ValidatorHistory<SignedAttestation> {
    pub fn check_for_attester_slashing(
        &self,
        attestation_data: &AttestationData,
    ) -> Result<Safe, NotSafe> {
        // Checking if history is empty
        let mut empty_select = self
            .conn
            .prepare("select 1 from signed_attestations limit 1")?;
        if !empty_select.exists(params![])? {
            return Ok(Safe {
                reason: ValidityReason::EmptyHistory,
            });
        }

        // Setting up utility vars
        let target_epoch: u64 = attestation_data.target.epoch.into();
        let i64_target_epoch = u64_to_i64(target_epoch);
        let source_epoch: u64 = attestation_data.source.epoch.into();
        let i64_source_epoch = u64_to_i64(source_epoch);

        // Checking if the attestation_data signing_root is already present in the db
        let mut same_hash_select = self
            .conn
            .prepare("select signing_root from signed_attestations where target_epoch = ?")?;
        let same_hash_select = same_hash_select.query_row(params![i64_target_epoch], |row| {
            let root: Vec<u8> = row.get(0)?;
            let signing_root = Hash256::from_slice(&root[..]);
            Ok(signing_root)
        });
        if let Ok(same_hash) = same_hash_select {
            if same_hash == Hash256::from_slice(&attestation_data.tree_hash_root()[..]) {
                return Ok(Safe {
                    reason: ValidityReason::SameVote,
                });
            } else {
                let mut double_vote_select = self.conn.prepare(
                "select target_epoch, source_epoch from signed_attestations where target_epoch = ?",
            )?;

                let conflicting_attest =
                    double_vote_select.query_row(params![i64_target_epoch], |row| {
                        let target_epoch: i64 = row.get(0)?;
                        let target_epoch = i64_to_u64(target_epoch);
                        let source_epoch: i64 = row.get(1)?;
                        let source_epoch = i64_to_u64(source_epoch);
                        Ok(SignedAttestation::new(
                            source_epoch,
                            target_epoch,
                            same_hash,
                        ))
                    })?;
                return Err(NotSafe::InvalidAttestation(InvalidAttestation::DoubleVote(
                    conflicting_attest,
                )));
            }
        }

        // Checking for PruningError (where attestation_data's target is smaller than the minimum target epoch in db)
        let mut min_select = self
            .conn
            .prepare("select min(target_epoch) from signed_attestations")?;
        let min_query = min_select.query_row(params![], |row| {
            let int: i64 = row.get(0)?;
            let int = i64_to_u64(int);
            Ok(int)
        })?;
        if attestation_data.target.epoch < min_query {
            return Err(NotSafe::PruningError);
        }

        // Checking if attestation_data is not surrounded by any previous votes
        let mut surrounded_select = self.conn.prepare("select target_epoch, source_epoch, signing_root from signed_attestations where target_epoch > ? order by target_epoch desc")?;
        let surrounded_query = surrounded_select.query_map(params![i64_target_epoch], |row| {
            let target: i64 = row.get(0)?;
            let source: i64 = row.get(1)?;
            let target = i64_to_u64(target);
            let source = i64_to_u64(source);
            let signing_root: Vec<u8> = row.get(2)?;
            Ok(SignedAttestation::new(
                source,
                target,
                Hash256::from_slice(&signing_root[..]),
            ))
        })?;
        let mut surrounded_vec = vec![];
        for elem in surrounded_query {
            surrounded_vec.push(elem?);
        }
        check_surrounded(attestation_data, &surrounded_vec[..])?;

        // Checking if attestation_Data is not surrounding any previous votes
        let mut surrounding_select = self.conn.prepare("select target_epoch, source_epoch, signing_root from signed_attestations where target_epoch > ? and target_epoch < ? order by target_epoch desc")?;
        let surrounding_query =
            surrounding_select.query_map(params![i64_source_epoch, i64_target_epoch], |row| {
                let target: i64 = row.get(0)?;
                let source: i64 = row.get(1)?;
                let target = i64_to_u64(target);
                let source = i64_to_u64(source);
                let signing_root: Vec<u8> = row.get(2)?;
                Ok(SignedAttestation::new(
                    source,
                    target,
                    Hash256::from_slice(&signing_root[..]),
                ))
            })?;
        let mut surrounding_vec = vec![];
        for elem in surrounding_query {
            surrounding_vec.push(elem?);
        }
        check_surrounding(attestation_data, &surrounding_vec[..])?;

        // Everything has been checked, return Valid
        Ok(Safe {
            reason: ValidityReason::Valid,
        })
    }
}

#[cfg(test)]
mod attestation_tests {
    use super::*;
    use crate::slashing_protection::{ValidatorHistory, SlashingProtection};
    use tempfile::NamedTempFile;
    use types::{AttestationData, Checkpoint, Epoch, Hash256, Slot};

    fn build_checkpoint(epoch_num: u64) -> Checkpoint {
        Checkpoint {
            epoch: Epoch::from(epoch_num),
            root: Hash256::zero(),
        }
    }

    fn attestation_data_builder(source: u64, target: u64) -> AttestationData {
        let source = build_checkpoint(source);
        let target = build_checkpoint(target);
        let index = 0u64;
        let slot = Slot::from(0u64);

        AttestationData {
            slot,
            index,
            beacon_block_root: Hash256::zero(),
            source,
            target,
        }
    }

    fn create_tmp() -> (ValidatorHistory<SignedAttestation>, NamedTempFile) {
        let attestation_file = NamedTempFile::new().expect("couldn't create temporary file");
        let filename = attestation_file.path();

        let attestation_history: ValidatorHistory<SignedAttestation> =
            ValidatorHistory::empty(filename).expect("IO error with file");

        (attestation_history, attestation_file)
    }

    #[test]
    fn valid_empty_history() {
        let (mut attestation_history, _attestation_file) = create_tmp();

        let attestation_data = attestation_data_builder(2, 3);
        let res = attestation_history.update_if_valid(&attestation_data);
        assert_eq!(res, Ok(()));
    }

    #[test]
    fn valid_middle_attestation() {
        let (mut attestation_history, _attestation_file) = create_tmp();

        let first = attestation_data_builder(0, 3);
        attestation_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");
        let second = attestation_data_builder(2, 5);
        attestation_history
            .update_if_valid(&second)
            .expect("should have inserted prev data");

        let attestation_data = attestation_data_builder(1, 4);
        let res = attestation_history.update_if_valid(&attestation_data);

        assert_eq!(res, Ok(()));
    }

    #[test]
    fn valid_last_attestation() {
        let (mut attestation_history, _attestation_file) = create_tmp();

        let first = attestation_data_builder(0, 1);
        attestation_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");
        let second = attestation_data_builder(0, 1);
        attestation_history
            .update_if_valid(&second)
            .expect("should have inserted prev data");

        let attestation_data = attestation_data_builder(2, 3);
        let res = attestation_history.update_if_valid(&attestation_data);

        assert_eq!(res, Ok(()));
    }

    #[test]
    fn valid_source_from_first_entry() {
        let (mut attestation_history, _attestation_file) = create_tmp();

        let first = attestation_data_builder(6, 7);
        attestation_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");

        let attestation_data = attestation_data_builder(6, 8);
        let res = attestation_history.update_if_valid(&attestation_data);

        assert_eq!(res, Ok(()));
    }

    #[test]
    fn invalid_source_from_first_entry() {
        let (mut attestation_history, _attestation_file) = create_tmp();

        let first = attestation_data_builder(6, 8);
        attestation_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");

        let attestation_data = attestation_data_builder(6, 7);
        let res = attestation_history.update_if_valid(&attestation_data);

        assert_eq!(res, Err(NotSafe::PruningError));
    }

    #[test]
    fn valid_same_vote_first() {
        let (mut attestation_history, _attestation_file) = create_tmp();

        let first = attestation_data_builder(0, 1);
        attestation_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");
        let second = attestation_data_builder(1, 2);
        attestation_history
            .update_if_valid(&second)
            .expect("should have inserted prev data");
        let third = attestation_data_builder(2, 3);
        attestation_history
            .update_if_valid(&third)
            .expect("should have inserted prev data");

        let attestation_data = first;
        let res = attestation_history.update_if_valid(&attestation_data);

        assert_eq!(res, Ok(()));
    }

    #[test]
    fn valid_same_vote_middle() {
        let (mut attestation_history, _attestation_file) = create_tmp();

        let first = attestation_data_builder(0, 1);
        attestation_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");
        let second = attestation_data_builder(1, 2);
        attestation_history
            .update_if_valid(&second)
            .expect("should have inserted prev data");
        let third = attestation_data_builder(2, 3);
        attestation_history
            .update_if_valid(&third)
            .expect("should have inserted prev data");

        let attestation_data = second;
        let res = attestation_history.update_if_valid(&attestation_data);

        assert_eq!(res, Ok(()));
    }

    #[test]
    fn valid_same_vote_last() {
        let (mut attestation_history, _attestation_file) = create_tmp();

        let first = attestation_data_builder(0, 1);
        attestation_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");
        let second = attestation_data_builder(1, 2);
        attestation_history
            .update_if_valid(&second)
            .expect("should have inserted prev data");
        let third = attestation_data_builder(2, 3);
        attestation_history
            .update_if_valid(&third)
            .expect("should have inserted prev data");

        let attestation_data = third;
        let res = attestation_history.update_if_valid(&attestation_data);

        assert_eq!(res, Ok(()));
    }

    #[test]
    fn invalid_double_vote_first() {
        let (mut attestation_history, _attestation_file) = create_tmp();

        let first = attestation_data_builder(1, 2);
        attestation_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");
        let second = attestation_data_builder(2, 3);
        attestation_history
            .update_if_valid(&second)
            .expect("should have inserted prev data");
        let third = attestation_data_builder(3, 4);
        attestation_history
            .update_if_valid(&third)
            .expect("should have inserted prev data");

        let attestation_data = attestation_data_builder(0, 2);
        let res = attestation_history.update_if_valid(&attestation_data);

        assert_eq!(
            res,
            Err(NotSafe::InvalidAttestation(InvalidAttestation::DoubleVote(
                SignedAttestation::from(&first)
            )))
        );
    }

    #[test]
    fn invalid_double_vote_middle() {
        let (mut attestation_history, _attestation_file) = create_tmp();

        let first = attestation_data_builder(0, 1);
        attestation_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");
        let second = attestation_data_builder(1, 3);
        attestation_history
            .update_if_valid(&second)
            .expect("should have inserted prev data");
        let third = attestation_data_builder(3, 4);
        attestation_history
            .update_if_valid(&third)
            .expect("should have inserted prev data");

        let attestation_data = attestation_data_builder(2, 3);
        let res = attestation_history.update_if_valid(&attestation_data);

        assert_eq!(
            res,
            Err(NotSafe::InvalidAttestation(InvalidAttestation::DoubleVote(
                SignedAttestation::from(&second)
            )))
        );
    }

    #[test]
    fn invalid_double_vote_last() {
        let (mut attestation_history, _attestation_file) = create_tmp();

        let first = attestation_data_builder(0, 1);
        attestation_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");
        let second = attestation_data_builder(1, 2);
        attestation_history
            .update_if_valid(&second)
            .expect("should have inserted prev data");
        let third = attestation_data_builder(3, 5);
        attestation_history
            .update_if_valid(&third)
            .expect("should have inserted prev data");

        let attestation_data = attestation_data_builder(4, 5);
        let res = attestation_history.update_if_valid(&attestation_data);

        assert_eq!(
            res,
            Err(NotSafe::InvalidAttestation(InvalidAttestation::DoubleVote(
                SignedAttestation::from(&third)
            )))
        );
    }

    #[test]
    fn invalid_double_vote_before() {
        let (mut attestation_history, _attestation_file) = create_tmp();

        let first = attestation_data_builder(2, 3);
        attestation_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");
        let second = attestation_data_builder(3, 4);
        attestation_history
            .update_if_valid(&second)
            .expect("should have inserted prev data");
        let third = attestation_data_builder(5, 6);
        attestation_history
            .update_if_valid(&third)
            .expect("should have inserted prev data");

        let attestation_data = attestation_data_builder(1, 3);
        let res = attestation_history.update_if_valid(&attestation_data);

        assert_eq!(
            res,
            Err(NotSafe::InvalidAttestation(InvalidAttestation::DoubleVote(
                SignedAttestation::from(&first)
            )))
        );
    }

    #[test]
    fn invalid_surround_first() {
        let (mut attestation_history, _attestation_file) = create_tmp();

        let first = attestation_data_builder(2, 3);
        attestation_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");
        let second = attestation_data_builder(4, 5);
        attestation_history
            .update_if_valid(&second)
            .expect("should have inserted prev data");
        let third = attestation_data_builder(6, 7);
        attestation_history
            .update_if_valid(&third)
            .expect("should have inserted prev data");

        let attestation_data = attestation_data_builder(1, 4);
        let res = attestation_history.update_if_valid(&attestation_data);

        assert_eq!(
            res,
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundingVote(SignedAttestation::from(&first))
            ))
        );
    }

    #[test]
    fn invalid_surround_middle() {
        let (mut attestation_history, _attestation_file) = create_tmp();

        let first = attestation_data_builder(2, 3);
        attestation_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");
        let second = attestation_data_builder(4, 5);
        attestation_history
            .update_if_valid(&second)
            .expect("should have inserted prev data");
        let third = attestation_data_builder(6, 7);
        attestation_history
            .update_if_valid(&third)
            .expect("should have inserted prev data");

        let attestation_data = attestation_data_builder(3, 6);
        let res = attestation_history.update_if_valid(&attestation_data);

        assert_eq!(
            res,
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundingVote(SignedAttestation::from(&second))
            ))
        );
    }

    #[test]
    fn invalid_surround_last() {
        let (mut attestation_history, _attestation_file) = create_tmp();

        let first = attestation_data_builder(2, 3);
        attestation_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");
        let second = attestation_data_builder(4, 5);
        attestation_history
            .update_if_valid(&second)
            .expect("should have inserted prev data");
        let third = attestation_data_builder(6, 7);
        attestation_history
            .update_if_valid(&third)
            .expect("should have inserted prev data");

        let attestation_data = attestation_data_builder(5, 8);
        let res = attestation_history.update_if_valid(&attestation_data);

        assert_eq!(
            res,
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundingVote(SignedAttestation::from(&third))
            ))
        );
    }

    #[test]
    fn invalid_surround_before() {
        let (mut attestation_history, _attestation_file) = create_tmp();
        let first = attestation_data_builder(221, 224);
        attestation_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");

        let attestation_data = attestation_data_builder(4, 227);
        let res = attestation_history.update_if_valid(&attestation_data);

        assert_eq!(
            res,
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundingVote(SignedAttestation::from(&first))
            ))
        );
    }

    #[test]
    fn invalid_surround_from_first_source() {
        let (mut attestation_history, _attestation_file) = create_tmp();
        let first = attestation_data_builder(2, 3);
        attestation_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");
        let second = attestation_data_builder(3, 4);
        attestation_history
            .update_if_valid(&second)
            .expect("should have inserted prev data");

        let attestation_data = attestation_data_builder(2, 5);
        let res = attestation_history.update_if_valid(&attestation_data);

        assert_eq!(
            res,
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundingVote(SignedAttestation::from(&second))
            ))
        );
    }

    #[test]
    fn invalid_surround_multiple_votes() {
        let (mut attestation_history, _attestation_file) = create_tmp();

        let first = attestation_data_builder(0, 1);
        attestation_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");
        let second = attestation_data_builder(1, 2);
        attestation_history
            .update_if_valid(&second)
            .expect("should have inserted prev data");
        let third = attestation_data_builder(2, 3);
        attestation_history
            .update_if_valid(&third)
            .expect("should have inserted prev data");
        let fourth = attestation_data_builder(3, 4);
        attestation_history
            .update_if_valid(&fourth)
            .expect("should have inserted prev data");

        let attestation_data = attestation_data_builder(1, 5);
        let res = attestation_history.update_if_valid(&attestation_data);

        assert_eq!(
            res,
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundingVote(SignedAttestation::from(&fourth))
            ))
        );
    }

    #[test]
    fn invalid_surrounded_middle_vote() {
        let (mut attestation_history, _attestation_file) = create_tmp();

        let first = attestation_data_builder(0, 1);
        attestation_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");
        let second = attestation_data_builder(1, 7);
        attestation_history
            .update_if_valid(&second)
            .expect("should have inserted prev data");
        let third = attestation_data_builder(8, 9);
        attestation_history
            .update_if_valid(&third)
            .expect("should have inserted prev data");

        let attestation_data = attestation_data_builder(2, 3);
        let res = attestation_history.update_if_valid(&attestation_data);

        assert_eq!(
            res,
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundedVote(SignedAttestation::from(&second))
            ))
        );
    }

    #[test]
    fn invalid_surrounded_last_vote() {
        let (mut attestation_history, _attestation_file) = create_tmp();

        let first = attestation_data_builder(0, 1);
        attestation_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");
        let second = attestation_data_builder(1, 2);
        attestation_history
            .update_if_valid(&second)
            .expect("should have inserted prev data");
        let third = attestation_data_builder(2, 7);
        attestation_history
            .update_if_valid(&third)
            .expect("should have inserted prev data");

        let attestation_data = attestation_data_builder(3, 4);
        let res = attestation_history.update_if_valid(&attestation_data);

        assert_eq!(
            res,
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundedVote(SignedAttestation::from(&third))
            ))
        );
    }

    #[test]
    fn invalid_surrounded_multiple_votes() {
        let (mut attestation_history, _attestation_file) = create_tmp();

        let first = attestation_data_builder(0, 1);
        attestation_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");
        let second = attestation_data_builder(1, 5);
        attestation_history
            .update_if_valid(&second)
            .expect("should have inserted prev data");
        let third = attestation_data_builder(2, 6);
        attestation_history
            .update_if_valid(&third)
            .expect("should have inserted prev data");

        let attestation_data = attestation_data_builder(3, 4);
        let res = attestation_history.update_if_valid(&attestation_data);

        println!("{:?}", third);
        assert_eq!(
            res,
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundedVote(SignedAttestation::from(&third))
            ))
        );
    }

    #[test]
    fn invalid_prunning_error_target_too_small() {
        let (mut attestation_history, _attestation_file) = create_tmp();
        let first = attestation_data_builder(221, 224);
        attestation_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");

        let attestation_data = attestation_data_builder(4, 5);
        let res = attestation_history.update_if_valid(&attestation_data);
        assert_eq!(res, Err(NotSafe::PruningError));
    }

    #[test]
    fn invalid_prunning_error_target_surrounded() {
        let (mut attestation_history, _attestation_file) = create_tmp();
        let first = attestation_data_builder(221, 224);
        attestation_history
            .update_if_valid(&first)
            .expect("should have inserted prev data");

        let attestation_data = attestation_data_builder(222, 223);
        let res = attestation_history.update_if_valid(&attestation_data);
        assert_eq!(res, Err(NotSafe::PruningError));
    }
}
