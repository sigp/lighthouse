#[cfg(test)]
mod test {
    use crate::attester_slashings::*;
    use crate::enums::*;
    use tree_hash::TreeHash;
    use types::{AttestationData, Checkpoint, Crosslink, Epoch, Hash256};

    fn build_checkpoint(epoch_num: u64) -> Checkpoint {
        Checkpoint {
            epoch: Epoch::from(epoch_num),
            root: Hash256::zero(),
        }
    }

    fn attestation_builder(source: u64, target: u64) -> AttestationData {
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
    fn valid_simple_test() {
        let mut history = vec![];
        history.push(SignedAttestation::new(0, 1, Hash256::random()));
        history.push(SignedAttestation::new(1, 2, Hash256::random()));

        let attestation_data = attestation_builder(2, 3);

        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Ok(Safe {
                insert_index: 2,
                reason: ValidData::Valid,
            })
        );
    }

    #[test]
    fn valid_empty_history() {
        let history = vec![];

        let attestation_data = attestation_builder(2, 3);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Ok(Safe {
                insert_index: 0,
                reason: ValidData::EmptyHistory,
            })
        );
    }

    #[test]
    fn valid_cast_same_vote() {
        let mut history = vec![];

        let attestation_data = attestation_builder(0, 1);

        history.push(SignedAttestation::new(
            0,
            1,
            Hash256::from_slice(&attestation_data.tree_hash_root()),
        ));
        history.push(SignedAttestation::new(1, 2, Hash256::random()));

        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Ok(Safe {
                insert_index: 1,
                reason: ValidData::SameVote,
            })
        );
    }

    #[test]
    fn invalid_double_vote() {
        let mut history = vec![];
        history.push(SignedAttestation::new(0, 1, Hash256::random()));
        history.push(SignedAttestation::new(1, 2, Hash256::random()));

        let attestation_data = attestation_builder(0, 1);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(InvalidAttestation::DoubleVote))
        );
    }

    #[test]
    fn invalid_surround_one_vote() {
        let mut history = vec![];
        history.push(SignedAttestation::new(0, 1, Hash256::random()));
        history.push(SignedAttestation::new(1, 2, Hash256::random()));
        history.push(SignedAttestation::new(2, 3, Hash256::random()));

        let attestation_data = attestation_builder(1, 4);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundingVote
            ))
        );
    }

    #[test]
    fn invalid_surround_one_vote_from_genesis() {
        let mut history = vec![];
        history.push(SignedAttestation::new(0, 1, Hash256::random()));
        history.push(SignedAttestation::new(1, 2, Hash256::random()));

        let attestation_data = attestation_builder(0, 3);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundingVote
            ))
        );
    }

    #[test]
    fn invalid_surround_one_vote_from_history_first_entry() {
        let mut history = vec![];
        history.push(SignedAttestation::new(2, 3, Hash256::random()));
        history.push(SignedAttestation::new(3, 4, Hash256::random()));

        let attestation_data = attestation_builder(2, 5);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundingVote
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

        let attestation_data = attestation_builder(1, 5);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundingVote
            ))
        );
    }

    #[test]
    fn invalid_surrounded_by_one_vote() {
        let mut history = vec![];
        history.push(SignedAttestation::new(0, 1, Hash256::random()));
        history.push(SignedAttestation::new(1, 6, Hash256::random()));

        let attestation_data = attestation_builder(2, 3);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundedVote
            ))
        );
    }

    #[test]
    fn invalid_surrounded_by_multiple_votes() {
        let mut history = vec![];
        history.push(SignedAttestation::new(0, 1, Hash256::random()));
        history.push(SignedAttestation::new(1, 6, Hash256::random()));
        history.push(SignedAttestation::new(2, 5, Hash256::random()));

        let attestation_data = attestation_builder(3, 4);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundedVote
            ))
        );
    }

    #[test]
    fn invalid_surrounded_by_one_vote_from_genesis() {
        let mut history = vec![];
        history.push(SignedAttestation::new(0, 1, Hash256::random()));
        history.push(SignedAttestation::new(0, 3, Hash256::random()));

        let attestation_data = attestation_builder(1, 2);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundedVote
            ))
        );
    }

    #[test]
    fn invalid_surrounding_last_vote() {
        let mut history = vec![];
        history.push(SignedAttestation::new(0, 1, Hash256::random()));
        history.push(SignedAttestation::new(0, 2, Hash256::random()));
        history.push(SignedAttestation::new(2, 3, Hash256::random()));
        history.push(SignedAttestation::new(4, 9, Hash256::random()));
        history.push(SignedAttestation::new(5, 10, Hash256::random()));
        history.push(SignedAttestation::new(6, 11, Hash256::random()));

        let attestation_data = attestation_builder(1, 8);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundingVote
            ))
        );
    }

    #[test]
    fn invalid_prunning_error_target_too_small() {
        let mut history = vec![];
        history.push(SignedAttestation::new(221, 224, Hash256::random()));

        let attestation_data = attestation_builder(4, 5);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::PruningError)
        );
    }

    #[test]
    fn invalid_prunning_error_source_too_small() {
        let mut history = vec![];
        history.push(SignedAttestation::new(221, 224, Hash256::random()));

        let attestation_data = attestation_builder(4, 227);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(InvalidAttestation::SurroundingVote))
        );
    }

    #[test]
    fn invalid_surrounding_first_vote() {
        let mut history = vec![];
        history.push(SignedAttestation::new(0, 1, Hash256::random()));
        history.push(SignedAttestation::new(0, 2, Hash256::random()));
        history.push(SignedAttestation::new(2, 3, Hash256::random()));

        let attestation_data = attestation_builder(1, 4);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundingVote
            ))
        );
    }
}
