#[cfg(test)]
mod attestation_tests {
    use crate::attester_slashings::*; // SCOTT
    use crate::enums::*; // SCOTT
    use tree_hash::TreeHash;
    use types::{
        AttestationData, AttestationDataAndCustodyBit, Checkpoint, Crosslink, Epoch, Hash256,
    };

    fn build_checkpoint(epoch_num: u64) -> Checkpoint {
        Checkpoint {
            epoch: Epoch::from(epoch_num),
            root: Hash256::zero(),
        }
    }

    fn attestation_data_and_custody_bit_builder(
        source: u64,
        target: u64,
    ) -> AttestationDataAndCustodyBit {
        let source = build_checkpoint(source);
        let target = build_checkpoint(target);
        let crosslink = Crosslink::default();

        let data = AttestationData {
            beacon_block_root: Hash256::zero(),
            source,
            target,
            crosslink,
        };

        AttestationDataAndCustodyBit {
            data,
            custody_bit: false,
        }
    }

    #[test]
    fn valid_empty_history() {
        let history = vec![];

        let attestation_data = attestation_data_and_custody_bit_builder(2, 3);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Ok(Safe {
                insert_index: 0,
                reason: ValidityReason::EmptyHistory,
            })
        );
    }

    #[test]
    fn valid_middle_attestation() {
        let mut history = vec![];
        history.push(SignedAttestation::new(0, 1, Hash256::random()));
        history.push(SignedAttestation::new(2, 3, Hash256::random()));

        let attestation_data = attestation_data_and_custody_bit_builder(1, 2);

        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Ok(Safe {
                insert_index: 1,
                reason: ValidityReason::Valid,
            })
        );
    }

    #[test]
    fn valid_last_attestation() {
        let mut history = vec![];
        history.push(SignedAttestation::new(0, 1, Hash256::random()));
        history.push(SignedAttestation::new(1, 2, Hash256::random()));

        let attestation_data = attestation_data_and_custody_bit_builder(2, 3);

        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Ok(Safe {
                insert_index: 2,
                reason: ValidityReason::Valid,
            })
        );
    }

    #[test]
    fn valid_source_before_history() {
        let mut history = vec![];
        history.push(SignedAttestation::new(6, 7, Hash256::random()));

        let attestation_data = attestation_data_and_custody_bit_builder(6, 8);

        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Ok(Safe {
                insert_index: 1,
                reason: ValidityReason::Valid,
            })
        );
    }

    #[test]
    fn invalid_source_before_history() {
        let mut history = vec![];
        history.push(SignedAttestation::new(6, 8, Hash256::random()));

        let attestation_data = attestation_data_and_custody_bit_builder(6, 7);

        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::PruningError)
        );
    }

    #[test]
    fn valid_same_vote_first() {
        let mut history = vec![];

        let attestation_data = attestation_data_and_custody_bit_builder(0, 1);

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
                insert_index: 0,
                reason: ValidityReason::SameVote,
            })
        );
    }

    #[test]
    fn valid_same_vote_middle() {
        let mut history = vec![];

        let attestation_data = attestation_data_and_custody_bit_builder(1, 2);

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
                insert_index: 1,
                reason: ValidityReason::SameVote,
            })
        );
    }

    #[test]
    fn valid_same_vote_last() {
        let mut history = vec![];

        let attestation_data = attestation_data_and_custody_bit_builder(2, 3);

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
                insert_index: 2,
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

        let attestation_data = attestation_data_and_custody_bit_builder(3, 4);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(InvalidAttestation::DoubleVote))
        );
    }

    #[test]
    fn invalid_double_vote_middle() {
        let mut history = vec![];
        history.push(SignedAttestation::new(3, 4, Hash256::random()));
        history.push(SignedAttestation::new(4, 5, Hash256::random()));
        history.push(SignedAttestation::new(5, 6, Hash256::random()));

        let attestation_data = attestation_data_and_custody_bit_builder(4, 5);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(InvalidAttestation::DoubleVote))
        );
    }

    #[test]
    fn invalid_double_vote_last() {
        let mut history = vec![];
        history.push(SignedAttestation::new(3, 4, Hash256::random()));
        history.push(SignedAttestation::new(4, 5, Hash256::random()));
        history.push(SignedAttestation::new(5, 6, Hash256::random()));

        let attestation_data = attestation_data_and_custody_bit_builder(5, 6);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(InvalidAttestation::DoubleVote))
        );
    }

    #[test]
    fn invalid_double_vote_before() {
        let mut history = vec![];
        history.push(SignedAttestation::new(3, 4, Hash256::random()));
        history.push(SignedAttestation::new(4, 5, Hash256::random()));
        history.push(SignedAttestation::new(5, 6, Hash256::random()));

        let attestation_data = attestation_data_and_custody_bit_builder(2, 4);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(InvalidAttestation::DoubleVote))
        );
    }

    #[test]
    fn invalid_surround_first() {
        let mut history = vec![];
        history.push(SignedAttestation::new(2, 3, Hash256::random()));
        history.push(SignedAttestation::new(4, 5, Hash256::random()));
        history.push(SignedAttestation::new(6, 7, Hash256::random()));

        let attestation_data = attestation_data_and_custody_bit_builder(1, 4);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundingVote
            ))
        );
    }

    #[test]
    fn invalid_surround_middle() {
        let mut history = vec![];
        history.push(SignedAttestation::new(2, 3, Hash256::random()));
        history.push(SignedAttestation::new(4, 5, Hash256::random()));
        history.push(SignedAttestation::new(6, 7, Hash256::random()));

        let attestation_data = attestation_data_and_custody_bit_builder(3, 6);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundingVote
            ))
        );
    }

    #[test]
    fn invalid_surround_last() {
        let mut history = vec![];
        history.push(SignedAttestation::new(2, 3, Hash256::random()));
        history.push(SignedAttestation::new(4, 5, Hash256::random()));
        history.push(SignedAttestation::new(6, 7, Hash256::random()));

        let attestation_data = attestation_data_and_custody_bit_builder(5, 8);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundingVote
            ))
        );
    }

    #[test]
    fn invalid_surround_before() {
        let mut history = vec![];
        history.push(SignedAttestation::new(221, 224, Hash256::random()));

        let attestation_data = attestation_data_and_custody_bit_builder(4, 227);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundingVote
            ))
        );
    }

    #[test]
    fn invalid_surround_from_first_source() {
        let mut history = vec![];
        history.push(SignedAttestation::new(2, 3, Hash256::random()));
        history.push(SignedAttestation::new(3, 4, Hash256::random()));

        let attestation_data = attestation_data_and_custody_bit_builder(2, 5);
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

        let attestation_data = attestation_data_and_custody_bit_builder(1, 5);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundingVote
            ))
        );
    }

    #[test]
    fn invalid_surrounded_first_vote() {
        let mut history = vec![];
        history.push(SignedAttestation::new(0, 1, Hash256::random()));
        history.push(SignedAttestation::new(0, 3, Hash256::random()));

        let attestation_data = attestation_data_and_custody_bit_builder(1, 2);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundedVote
            ))
        );
    }

    #[test]
    fn invalid_surrounded_middle_vote() {
        let mut history = vec![];
        history.push(SignedAttestation::new(1, 2, Hash256::random()));
        history.push(SignedAttestation::new(1, 6, Hash256::random()));
        history.push(SignedAttestation::new(6, 7, Hash256::random()));

        let attestation_data = attestation_data_and_custody_bit_builder(2, 3);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundedVote
            ))
        );
    }

    #[test]
    fn invalid_surrounded_last_vote() {
        let mut history = vec![];
        history.push(SignedAttestation::new(1, 2, Hash256::random()));
        history.push(SignedAttestation::new(1, 6, Hash256::random()));

        let attestation_data = attestation_data_and_custody_bit_builder(2, 3);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundedVote
            ))
        );
    }

    #[test]
    fn invalid_surrounded_multiple_votes() {
        let mut history = vec![];
        history.push(SignedAttestation::new(0, 1, Hash256::random()));
        history.push(SignedAttestation::new(1, 6, Hash256::random()));
        history.push(SignedAttestation::new(2, 5, Hash256::random()));

        let attestation_data = attestation_data_and_custody_bit_builder(3, 4);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::InvalidAttestation(
                InvalidAttestation::SurroundedVote
            ))
        );
    }

    #[test]
    fn invalid_prunning_error_target_too_small() {
        let mut history = vec![];
        history.push(SignedAttestation::new(221, 224, Hash256::random()));

        let attestation_data = attestation_data_and_custody_bit_builder(4, 5);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::PruningError)
        );
    }

    #[test]
    fn invalid_prunning_error_target_surrounded() {
        let mut history = vec![];
        history.push(SignedAttestation::new(221, 224, Hash256::random()));

        let attestation_data = attestation_data_and_custody_bit_builder(222, 223);
        assert_eq!(
            check_for_attester_slashing(&attestation_data, &history[..]),
            Err(NotSafe::PruningError)
        );
    }
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
