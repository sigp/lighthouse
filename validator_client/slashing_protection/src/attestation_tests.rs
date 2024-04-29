#![cfg(test)]

use crate::test_utils::*;
use crate::*;
use types::{AttestationData, Checkpoint, Epoch, Slot};

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

/// Create a signed attestation from `attestation`, assuming the default domain.
fn signed_att(attestation: &AttestationData) -> SignedAttestation {
    SignedAttestation::from_attestation(attestation, DEFAULT_DOMAIN)
}

#[test]
fn valid_empty_history() {
    StreamTest {
        cases: vec![Test::single(attestation_data_builder(2, 3))],
        ..StreamTest::default()
    }
    .run()
}

#[test]
fn valid_genesis() {
    StreamTest {
        cases: vec![Test::single(attestation_data_builder(0, 0))],
        ..StreamTest::default()
    }
    .run()
}

#[test]
fn valid_out_of_order_attestation() {
    StreamTest {
        cases: vec![
            Test::single(attestation_data_builder(0, 3)),
            Test::single(attestation_data_builder(2, 5)),
            Test::single(attestation_data_builder(1, 4)),
        ],
        ..StreamTest::default()
    }
    .run()
}

#[test]
fn valid_repeat_attestation() {
    StreamTest {
        cases: vec![
            Test::single(attestation_data_builder(0, 1)),
            Test::single(attestation_data_builder(0, 1)).expect_same_data(),
        ],
        ..StreamTest::default()
    }
    .run()
}

#[test]
fn valid_source_from_first_entry() {
    StreamTest {
        cases: vec![
            Test::single(attestation_data_builder(6, 7)),
            Test::single(attestation_data_builder(6, 8)),
        ],
        ..StreamTest::default()
    }
    .run()
}

#[test]
fn valid_multiple_validators_double_vote() {
    StreamTest {
        registered_validators: vec![pubkey(0), pubkey(1)],
        cases: vec![
            Test::with_pubkey(pubkey(0), attestation_data_builder(0, 1)),
            Test::with_pubkey(pubkey(1), attestation_data_builder(0, 1)),
        ],
    }
    .run()
}

#[test]
fn valid_vote_chain_repeat_first() {
    StreamTest {
        cases: vec![
            Test::single(attestation_data_builder(0, 1)),
            Test::single(attestation_data_builder(1, 2)),
            Test::single(attestation_data_builder(2, 3)),
            Test::single(attestation_data_builder(0, 1)).expect_same_data(),
        ],
        ..StreamTest::default()
    }
    .run()
}

#[test]
fn valid_vote_chain_repeat_middle() {
    StreamTest {
        cases: vec![
            Test::single(attestation_data_builder(0, 1)),
            Test::single(attestation_data_builder(1, 2)),
            Test::single(attestation_data_builder(2, 3)),
            Test::single(attestation_data_builder(1, 2)).expect_same_data(),
        ],
        ..StreamTest::default()
    }
    .run()
}

#[test]
fn valid_vote_chain_repeat_last() {
    StreamTest {
        cases: vec![
            Test::single(attestation_data_builder(0, 1)),
            Test::single(attestation_data_builder(1, 2)),
            Test::single(attestation_data_builder(2, 3)),
            Test::single(attestation_data_builder(2, 3)).expect_same_data(),
        ],
        ..StreamTest::default()
    }
    .run()
}

#[test]
fn valid_multiple_validators_not_surrounding() {
    // Attestations that would be problematic if they came from the same validator, but are OK
    // coming from different validators.
    StreamTest {
        registered_validators: vec![pubkey(0), pubkey(1)],
        cases: vec![
            Test::with_pubkey(pubkey(0), attestation_data_builder(0, 10)),
            Test::with_pubkey(pubkey(0), attestation_data_builder(10, 20)),
            Test::with_pubkey(pubkey(1), attestation_data_builder(1, 9)),
            Test::with_pubkey(pubkey(1), attestation_data_builder(9, 21)),
        ],
    }
    .run()
}

#[test]
fn invalid_source_exceeds_target() {
    StreamTest {
        cases: vec![Test::single(attestation_data_builder(1, 0))
            .expect_invalid_att(InvalidAttestation::SourceExceedsTarget)],
        ..StreamTest::default()
    }
    .run()
}

#[test]
fn invalid_unregistered_validator() {
    StreamTest {
        registered_validators: vec![],
        cases: vec![
            Test::single(attestation_data_builder(2, 3)).expect_result(Err(
                NotSafe::UnregisteredValidator(pubkey(DEFAULT_VALIDATOR_INDEX)),
            )),
        ],
    }
    .run()
}

#[test]
fn invalid_double_vote_diff_source() {
    let first = attestation_data_builder(0, 2);
    StreamTest {
        cases: vec![
            Test::single(first.clone()),
            Test::single(attestation_data_builder(1, 2))
                .expect_invalid_att(InvalidAttestation::DoubleVote(signed_att(&first))),
        ],
        ..StreamTest::default()
    }
    .run()
}

#[test]
fn invalid_double_vote_diff_target() {
    let first = attestation_data_builder(0, 2);
    let mut second = attestation_data_builder(0, 2);
    second.target.root = Hash256::random();
    assert_ne!(first, second);
    StreamTest {
        cases: vec![
            Test::single(first.clone()),
            Test::single(second)
                .expect_invalid_att(InvalidAttestation::DoubleVote(signed_att(&first))),
        ],
        ..StreamTest::default()
    }
    .run()
}

#[test]
fn invalid_double_vote_diff_data() {
    let first = attestation_data_builder(0, 2);
    let mut second = attestation_data_builder(0, 2);
    second.beacon_block_root = Hash256::random();
    assert_ne!(first, second);
    StreamTest {
        cases: vec![
            Test::single(first.clone()),
            Test::single(second)
                .expect_invalid_att(InvalidAttestation::DoubleVote(signed_att(&first))),
        ],
        ..StreamTest::default()
    }
    .run()
}

#[test]
fn invalid_double_vote_diff_domain() {
    let first = attestation_data_builder(0, 2);
    let domain1 = Hash256::from_low_u64_le(1);
    let domain2 = Hash256::from_low_u64_le(2);

    StreamTest {
        cases: vec![
            Test::single(first.clone()).with_domain(domain1),
            Test::single(first.clone())
                .with_domain(domain2)
                .expect_invalid_att(InvalidAttestation::DoubleVote(
                    SignedAttestation::from_attestation(&first, domain1),
                )),
        ],
        ..StreamTest::default()
    }
    .run()
}

#[test]
fn invalid_double_vote_diff_source_multi() {
    let first = attestation_data_builder(0, 2);
    let second = attestation_data_builder(1, 3);
    let third = attestation_data_builder(2, 4);
    StreamTest {
        cases: vec![
            Test::single(first.clone()),
            Test::single(second.clone()),
            Test::single(third.clone()),
            Test::single(attestation_data_builder(1, 2))
                .expect_invalid_att(InvalidAttestation::DoubleVote(signed_att(&first))),
            Test::single(attestation_data_builder(2, 3))
                .expect_invalid_att(InvalidAttestation::DoubleVote(signed_att(&second))),
            Test::single(attestation_data_builder(3, 4))
                .expect_invalid_att(InvalidAttestation::DoubleVote(signed_att(&third))),
        ],
        ..StreamTest::default()
    }
    .run()
}

#[test]
fn invalid_surrounding_single() {
    let first = attestation_data_builder(2, 3);
    let second = attestation_data_builder(4, 5);
    let third = attestation_data_builder(6, 7);
    StreamTest {
        cases: vec![
            Test::single(first.clone()),
            Test::single(second.clone()),
            Test::single(third.clone()),
            Test::single(attestation_data_builder(1, 4)).expect_invalid_att(
                InvalidAttestation::NewSurroundsPrev {
                    prev: signed_att(&first),
                },
            ),
            Test::single(attestation_data_builder(3, 6)).expect_invalid_att(
                InvalidAttestation::NewSurroundsPrev {
                    prev: signed_att(&second),
                },
            ),
            Test::single(attestation_data_builder(5, 8)).expect_invalid_att(
                InvalidAttestation::NewSurroundsPrev {
                    prev: signed_att(&third),
                },
            ),
        ],
        ..StreamTest::default()
    }
    .run()
}

#[test]
fn invalid_surrounding_from_first_source() {
    let first = attestation_data_builder(2, 3);
    let second = attestation_data_builder(3, 4);
    StreamTest {
        cases: vec![
            Test::single(first),
            Test::single(second.clone()),
            Test::single(attestation_data_builder(2, 5)).expect_invalid_att(
                InvalidAttestation::NewSurroundsPrev {
                    prev: signed_att(&second),
                },
            ),
        ],
        ..StreamTest::default()
    }
    .run()
}

#[test]
fn invalid_surrounding_multiple_votes() {
    let first = attestation_data_builder(0, 1);
    let second = attestation_data_builder(1, 2);
    let third = attestation_data_builder(2, 3);
    StreamTest {
        cases: vec![
            Test::single(first),
            Test::single(second),
            Test::single(third.clone()),
            Test::single(attestation_data_builder(0, 4)).expect_invalid_att(
                InvalidAttestation::NewSurroundsPrev {
                    prev: signed_att(&third),
                },
            ),
        ],
        ..StreamTest::default()
    }
    .run()
}

#[test]
fn invalid_prev_surrounds_new() {
    let first = attestation_data_builder(0, 7);
    StreamTest {
        cases: vec![
            Test::single(first.clone()),
            Test::single(attestation_data_builder(1, 6)).expect_invalid_att(
                InvalidAttestation::PrevSurroundsNew {
                    prev: signed_att(&first),
                },
            ),
        ],
        ..StreamTest::default()
    }
    .run()
}

#[test]
fn invalid_prev_surrounds_new_multiple() {
    let first = attestation_data_builder(0, 4);
    let second = attestation_data_builder(1, 7);
    let third = attestation_data_builder(8, 10);
    StreamTest {
        cases: vec![
            Test::single(first.clone()),
            Test::single(second.clone()),
            Test::single(third.clone()),
            Test::single(attestation_data_builder(9, 9)).expect_invalid_att(
                InvalidAttestation::PrevSurroundsNew {
                    prev: signed_att(&third),
                },
            ),
            Test::single(attestation_data_builder(2, 6)).expect_invalid_att(
                InvalidAttestation::PrevSurroundsNew {
                    prev: signed_att(&second),
                },
            ),
            Test::single(attestation_data_builder(1, 2)).expect_invalid_att(
                InvalidAttestation::PrevSurroundsNew {
                    prev: signed_att(&first),
                },
            ),
        ],
        ..StreamTest::default()
    }
    .run()
}
