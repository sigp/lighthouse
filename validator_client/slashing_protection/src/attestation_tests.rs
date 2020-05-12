#![cfg(test)]

use crate::test_utils::*;
use crate::*;
use types::{AttestationData, Checkpoint, Epoch, Hash256, Slot};

pub fn build_checkpoint(epoch_num: u64) -> Checkpoint {
    Checkpoint {
        epoch: Epoch::from(epoch_num),
        root: Hash256::zero(),
    }
}

pub fn attestation_data_builder(source: u64, target: u64) -> AttestationData {
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

#[test]
fn valid_empty_history() {
    AttestationStreamTest {
        cases: vec![AttestationTest::single(attestation_data_builder(2, 3))],
        ..AttestationStreamTest::default()
    }
    .run()
}

#[test]
fn valid_genesis() {
    AttestationStreamTest {
        cases: vec![AttestationTest::single(attestation_data_builder(0, 0))],
        ..AttestationStreamTest::default()
    }
    .run()
}

#[test]
fn valid_out_of_order_attestation() {
    AttestationStreamTest {
        cases: vec![
            AttestationTest::single(attestation_data_builder(0, 3)),
            AttestationTest::single(attestation_data_builder(2, 5)),
            AttestationTest::single(attestation_data_builder(1, 4)),
        ],
        ..AttestationStreamTest::default()
    }
    .run()
}

#[test]
fn valid_repeat_attestation() {
    AttestationStreamTest {
        cases: vec![
            AttestationTest::single(attestation_data_builder(0, 1)),
            AttestationTest::single(attestation_data_builder(0, 1)).expect_same_data(),
        ],
        ..AttestationStreamTest::default()
    }
    .run()
}

#[test]
fn valid_source_from_first_entry() {
    AttestationStreamTest {
        cases: vec![
            AttestationTest::single(attestation_data_builder(6, 7)),
            AttestationTest::single(attestation_data_builder(6, 8)),
        ],
        ..AttestationStreamTest::default()
    }
    .run()
}

#[test]
fn valid_multiple_validators_double_vote() {
    AttestationStreamTest {
        registered_validators: vec![pubkey(0), pubkey(1)],
        cases: vec![
            AttestationTest::with_pubkey(pubkey(0), attestation_data_builder(0, 1)),
            AttestationTest::with_pubkey(pubkey(1), attestation_data_builder(0, 1)),
        ],
    }
    .run()
}

#[test]
fn valid_vote_chain_repeat_first() {
    AttestationStreamTest {
        cases: vec![
            AttestationTest::single(attestation_data_builder(0, 1)),
            AttestationTest::single(attestation_data_builder(1, 2)),
            AttestationTest::single(attestation_data_builder(2, 3)),
            AttestationTest::single(attestation_data_builder(0, 1)).expect_same_data(),
        ],
        ..AttestationStreamTest::default()
    }
    .run()
}

#[test]
fn valid_vote_chain_repeat_middle() {
    AttestationStreamTest {
        cases: vec![
            AttestationTest::single(attestation_data_builder(0, 1)),
            AttestationTest::single(attestation_data_builder(1, 2)),
            AttestationTest::single(attestation_data_builder(2, 3)),
            AttestationTest::single(attestation_data_builder(1, 2)).expect_same_data(),
        ],
        ..AttestationStreamTest::default()
    }
    .run()
}

#[test]
fn valid_vote_chain_repeat_last() {
    AttestationStreamTest {
        cases: vec![
            AttestationTest::single(attestation_data_builder(0, 1)),
            AttestationTest::single(attestation_data_builder(1, 2)),
            AttestationTest::single(attestation_data_builder(2, 3)),
            AttestationTest::single(attestation_data_builder(2, 3)).expect_same_data(),
        ],
        ..AttestationStreamTest::default()
    }
    .run()
}

#[test]
fn invalid_unregistered_validator() {
    AttestationStreamTest {
        registered_validators: vec![],
        cases: vec![
            AttestationTest::single(attestation_data_builder(2, 3)).expect_result(Err(
                NotSafe::UnregisteredValidator(pubkey(DEFAULT_VALIDATOR_INDEX)),
            )),
        ],
    }
    .run()
}

#[test]
fn invalid_double_vote_diff_source() {
    let first = attestation_data_builder(0, 2);
    AttestationStreamTest {
        cases: vec![
            AttestationTest::single(first.clone()),
            AttestationTest::single(attestation_data_builder(1, 2)).expect_invalid_att(
                InvalidAttestation::DoubleVote(SignedAttestation::from(&first)),
            ),
        ],
        ..AttestationStreamTest::default()
    }
    .run()
}

#[test]
fn invalid_double_vote_diff_target() {
    let first = attestation_data_builder(0, 2);
    let mut second = attestation_data_builder(0, 2);
    second.target.root = Hash256::random();
    assert_ne!(first, second);
    AttestationStreamTest {
        cases: vec![
            AttestationTest::single(first.clone()),
            AttestationTest::single(second).expect_invalid_att(InvalidAttestation::DoubleVote(
                SignedAttestation::from(&first),
            )),
        ],
        ..AttestationStreamTest::default()
    }
    .run()
}

#[test]
fn invalid_double_vote_diff_source_multi() {
    let first = attestation_data_builder(0, 2);
    let second = attestation_data_builder(1, 3);
    let third = attestation_data_builder(2, 4);
    AttestationStreamTest {
        cases: vec![
            AttestationTest::single(first.clone()),
            AttestationTest::single(second.clone()),
            AttestationTest::single(third.clone()),
            AttestationTest::single(attestation_data_builder(1, 2)).expect_invalid_att(
                InvalidAttestation::DoubleVote(SignedAttestation::from(&first)),
            ),
            AttestationTest::single(attestation_data_builder(2, 3)).expect_invalid_att(
                InvalidAttestation::DoubleVote(SignedAttestation::from(&second)),
            ),
            AttestationTest::single(attestation_data_builder(3, 4)).expect_invalid_att(
                InvalidAttestation::DoubleVote(SignedAttestation::from(&third)),
            ),
        ],
        ..AttestationStreamTest::default()
    }
    .run()
}

#[test]
fn invalid_surrounding_single() {
    let first = attestation_data_builder(2, 3);
    let second = attestation_data_builder(4, 5);
    let third = attestation_data_builder(6, 7);
    AttestationStreamTest {
        cases: vec![
            AttestationTest::single(first.clone()),
            AttestationTest::single(second.clone()),
            AttestationTest::single(third.clone()),
            AttestationTest::single(attestation_data_builder(1, 4)).expect_invalid_att(
                InvalidAttestation::NewSurroundsPrev {
                    prev: SignedAttestation::from(&first),
                },
            ),
            AttestationTest::single(attestation_data_builder(3, 6)).expect_invalid_att(
                InvalidAttestation::NewSurroundsPrev {
                    prev: SignedAttestation::from(&second),
                },
            ),
            AttestationTest::single(attestation_data_builder(5, 8)).expect_invalid_att(
                InvalidAttestation::NewSurroundsPrev {
                    prev: SignedAttestation::from(&third),
                },
            ),
        ],
        ..AttestationStreamTest::default()
    }
    .run()
}

#[test]
fn invalid_surrounding_from_first_source() {
    let first = attestation_data_builder(2, 3);
    let second = attestation_data_builder(3, 4);
    AttestationStreamTest {
        cases: vec![
            AttestationTest::single(first.clone()),
            AttestationTest::single(second.clone()),
            AttestationTest::single(attestation_data_builder(2, 5)).expect_invalid_att(
                InvalidAttestation::NewSurroundsPrev {
                    prev: SignedAttestation::from(&second),
                },
            ),
        ],
        ..AttestationStreamTest::default()
    }
    .run()
}

#[test]
fn invalid_surrounding_multiple_votes() {
    let first = attestation_data_builder(0, 1);
    let second = attestation_data_builder(1, 2);
    let third = attestation_data_builder(2, 3);
    AttestationStreamTest {
        cases: vec![
            AttestationTest::single(first.clone()),
            AttestationTest::single(second.clone()),
            AttestationTest::single(third.clone()),
            AttestationTest::single(attestation_data_builder(0, 4)).expect_invalid_att(
                InvalidAttestation::NewSurroundsPrev {
                    prev: SignedAttestation::from(&third),
                },
            ),
        ],
        ..AttestationStreamTest::default()
    }
    .run()
}

#[test]
fn invalid_prev_surrounds_new() {
    let first = attestation_data_builder(0, 7);
    AttestationStreamTest {
        cases: vec![
            AttestationTest::single(first.clone()),
            AttestationTest::single(attestation_data_builder(1, 6)).expect_invalid_att(
                InvalidAttestation::PrevSurroundsNew {
                    prev: SignedAttestation::from(&first),
                },
            ),
        ],
        ..AttestationStreamTest::default()
    }
    .run()
}

#[test]
fn invalid_prev_surrounds_new_multiple() {
    let first = attestation_data_builder(0, 4);
    let second = attestation_data_builder(1, 7);
    let third = attestation_data_builder(8, 10);
    AttestationStreamTest {
        cases: vec![
            AttestationTest::single(first.clone()),
            AttestationTest::single(second.clone()),
            AttestationTest::single(third.clone()),
            AttestationTest::single(attestation_data_builder(9, 9)).expect_invalid_att(
                InvalidAttestation::PrevSurroundsNew {
                    prev: SignedAttestation::from(&third),
                },
            ),
            AttestationTest::single(attestation_data_builder(2, 6)).expect_invalid_att(
                InvalidAttestation::PrevSurroundsNew {
                    prev: SignedAttestation::from(&second),
                },
            ),
            AttestationTest::single(attestation_data_builder(1, 2)).expect_invalid_att(
                InvalidAttestation::PrevSurroundsNew {
                    prev: SignedAttestation::from(&first),
                },
            ),
        ],
        ..AttestationStreamTest::default()
    }
    .run()
}

// FIXME(slashing): overlapping attestations from multiple validators, source exceeds epoch test
