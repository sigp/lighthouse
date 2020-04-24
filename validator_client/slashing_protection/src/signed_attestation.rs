use crate::validator_history::ValidatorHistory;
use crate::{NotSafe, Safe, ValidityReason};
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
            signing_root: attestation.tree_hash_root(),
        }
    }
}

#[derive(PartialEq, Debug)]
pub enum InvalidAttestation {
    DoubleVote(SignedAttestation),
    NewSurroundsPrev { prev: SignedAttestation },
    PrevSurroundsNew { prev: SignedAttestation },
}

/// Checks if the attestation is valid, invalid, or slashable, and returns accordingly.
impl ValidatorHistory<SignedAttestation> {
    pub fn check_for_attester_slashing(
        &self,
        attestation_data: &AttestationData,
    ) -> Result<Safe, NotSafe> {
        let att_source_epoch = attestation_data.source.epoch;
        let att_target_epoch = attestation_data.target.epoch;
        let conn = self.conn_pool.get()?;

        // Checking if history is empty
        let mut empty_select = conn.prepare("SELECT 1 FROM signed_attestations LIMIT 1")?;
        if !empty_select.exists(params![])? {
            return Ok(Safe {
                reason: ValidityReason::EmptyHistory,
            });
        }

        // Checking if the attestation_data signing_root is already present in the db
        let mut same_hash_select =
            conn.prepare("SELECT signing_root FROM signed_attestations WHERE target_epoch = ?")?;
        let same_hash_select = same_hash_select.query_row(params![att_target_epoch], |row| {
            let root: Vec<u8> = row.get(0)?;
            let signing_root = Hash256::from_slice(&root[..]);
            Ok(signing_root)
        });
        // FIXME(slashing): think about selecting more than 1 row here (DB shouldn't contain
        // data that's already slashable, right?)
        if let Ok(same_hash) = same_hash_select {
            if same_hash == attestation_data.tree_hash_root() {
                return Ok(Safe {
                    reason: ValidityReason::SameData,
                });
            } else {
                let mut double_vote_select = conn.prepare(
                    "SELECT target_epoch, source_epoch
                     FROM signed_attestations WHERE target_epoch = ?",
                )?;

                let conflicting_attest =
                    double_vote_select.query_row(params![att_target_epoch], |row| {
                        let target_epoch = row.get(0)?;
                        let source_epoch = row.get(1)?;
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

        // Checking for PruningError (where attestation_data's target is smaller than the minimum
        // target epoch in db)
        let mut min_select = conn.prepare("SELECT MIN(target_epoch) FROM signed_attestations")?;
        let min_target_epoch: Epoch = min_select.query_row(params![], |row| row.get(0))?;
        if att_target_epoch < min_target_epoch {
            return Err(NotSafe::PruningError);
        }

        // Check that no previous votes are surrounding `attestation_data`.
        let surrounding_attestations = conn
            .prepare(
                "SELECT source_epoch, target_epoch, signing_root
                 FROM signed_attestations
                 WHERE source_epoch < ?1 AND target_epoch > ?2
                 ORDER BY target_epoch DESC",
            )?
            .query_map(params![att_source_epoch, att_target_epoch], |row| {
                let source = row.get(0)?;
                let target = row.get(1)?;
                let signing_root: Vec<u8> = row.get(2)?;
                Ok(SignedAttestation::new(
                    source,
                    target,
                    Hash256::from_slice(&signing_root[..]),
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        if let Some(prev) = surrounding_attestations.first().cloned() {
            return Err(NotSafe::InvalidAttestation(
                InvalidAttestation::PrevSurroundsNew { prev },
            ));
        }

        // Check that no previous votes are surrounded by `attestation_data`.
        let surrounded_attestations = conn
            .prepare(
                "SELECT source_epoch, target_epoch, signing_root
                 FROM signed_attestations
                 WHERE source_epoch > ?1 and target_epoch < ?2
                 ORDER BY target_epoch DESC",
            )?
            .query_map(params![att_source_epoch, att_target_epoch], |row| {
                let source = row.get(0)?;
                let target = row.get(1)?;
                let signing_root: Vec<u8> = row.get(2)?;
                Ok(SignedAttestation::new(
                    source,
                    target,
                    Hash256::from_slice(&signing_root[..]),
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        if let Some(prev) = surrounded_attestations.first().cloned() {
            return Err(NotSafe::InvalidAttestation(
                InvalidAttestation::NewSurroundsPrev { prev },
            ));
        }

        // Everything has been checked, return Valid
        Ok(Safe {
            reason: ValidityReason::Valid,
        })
    }
}

#[cfg(test)]
mod attestation_tests {
    use super::*;
    use crate::validator_history::SlashingProtection;
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
            ValidatorHistory::new(filename, None).expect("IO error with file");

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
                InvalidAttestation::NewSurroundsPrev {
                    prev: SignedAttestation::from(&first)
                }
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
                InvalidAttestation::NewSurroundsPrev {
                    prev: SignedAttestation::from(&second)
                }
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
                InvalidAttestation::NewSurroundsPrev {
                    prev: SignedAttestation::from(&third)
                }
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
