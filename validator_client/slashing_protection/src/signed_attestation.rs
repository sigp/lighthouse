use std::convert::From;
use tree_hash::TreeHash;
use types::{AttestationData, Epoch, Hash256};

#[derive(Clone, Debug, PartialEq)]
pub struct SignedAttestation {
    pub source_epoch: Epoch,
    pub target_epoch: Epoch,
    pub signing_root: Hash256,
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

// FIXME(slashing): fix these tests
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
