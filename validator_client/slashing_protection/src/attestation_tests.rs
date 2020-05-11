#![cfg(test)]

use crate::*;
use tempfile::NamedTempFile;
use types::{
    test_utils::generate_deterministic_keypair, AttestationData, Checkpoint, Epoch, Hash256, Slot,
};

pub const DEFAULT_VALIDATOR_INDEX: usize = 0;

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

pub fn pubkey(index: usize) -> PublicKey {
    generate_deterministic_keypair(index).pk
}

pub struct AttestationTest {
    pubkey: PublicKey,
    attestation: AttestationData,
    expected: Result<Safe, NotSafe>,
}

impl AttestationTest {
    pub fn single(attestation: AttestationData) -> Self {
        Self::with_pubkey(pubkey(DEFAULT_VALIDATOR_INDEX), attestation)
    }

    pub fn with_pubkey(pubkey: PublicKey, attestation: AttestationData) -> Self {
        Self {
            pubkey,
            attestation,
            expected: Ok(Safe {
                reason: ValidityReason::Valid,
            }),
        }
    }

    pub fn expect_result(mut self, result: Result<Safe, NotSafe>) -> Self {
        self.expected = result;
        self
    }

    pub fn expect_invalid_att(self, error: InvalidAttestation) -> Self {
        self.expect_result(Err(NotSafe::InvalidAttestation(error)))
    }

    pub fn expect_same_data(self) -> Self {
        self.expect_result(Ok(Safe {
            reason: ValidityReason::SameData,
        }))
    }
}

pub struct AttestationStreamTest {
    /// Validators to register.
    pub registered_validators: Vec<PublicKey>,
    /// Vector of attestations and the value expected when calling `check_and_insert_attestation`.
    pub attestations: Vec<AttestationTest>,
}

impl Default for AttestationStreamTest {
    fn default() -> Self {
        Self {
            registered_validators: vec![pubkey(DEFAULT_VALIDATOR_INDEX)],
            attestations: vec![],
        }
    }
}

impl AttestationStreamTest {
    pub fn run(&self) {
        let slashing_db_file = NamedTempFile::new().expect("couldn't create temporary file");
        let slashing_db = SlashingDatabase::create(slashing_db_file.path()).unwrap();

        for pubkey in &self.registered_validators {
            slashing_db.register_validator(pubkey).unwrap();
        }

        for (i, test) in self.attestations.iter().enumerate() {
            assert_eq!(
                slashing_db.check_and_insert_attestation(&test.pubkey, &test.attestation),
                test.expected,
                "attestation {} not processed as expected",
                i
            );
        }
    }
}

#[test]
fn valid_empty_history() {
    AttestationStreamTest {
        attestations: vec![AttestationTest::single(attestation_data_builder(2, 3))],
        ..AttestationStreamTest::default()
    }
    .run()
}

#[test]
fn valid_genesis() {
    AttestationStreamTest {
        attestations: vec![AttestationTest::single(attestation_data_builder(0, 0))],
        ..AttestationStreamTest::default()
    }
    .run()
}

#[test]
fn valid_out_of_order_attestation() {
    AttestationStreamTest {
        attestations: vec![
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
        attestations: vec![
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
        attestations: vec![
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
        attestations: vec![
            AttestationTest::with_pubkey(pubkey(0), attestation_data_builder(0, 1)),
            AttestationTest::with_pubkey(pubkey(1), attestation_data_builder(0, 1)),
        ],
    }
    .run()
}

/* FIXME(slashing): reconsider
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
*/

#[test]
fn valid_vote_chain_repeat_first() {
    AttestationStreamTest {
        attestations: vec![
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
        attestations: vec![
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
        attestations: vec![
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
fn invalid_double_vote_diff_source() {
    let first = attestation_data_builder(0, 2);
    AttestationStreamTest {
        attestations: vec![
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
        attestations: vec![
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
        attestations: vec![
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
        attestations: vec![
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
        attestations: vec![
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
        attestations: vec![
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

/* FIXME(slashing): finish prev surrounds new tests
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
*/
