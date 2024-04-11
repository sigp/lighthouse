#![cfg(test)]

use super::*;
use crate::test_utils::*;
use types::{BeaconBlockHeader, Slot};

pub fn block(slot: u64) -> BeaconBlockHeader {
    BeaconBlockHeader {
        slot: Slot::new(slot),
        proposer_index: 0,
        parent_root: Hash256::random(),
        state_root: Hash256::random(),
        body_root: Hash256::random(),
    }
}

#[test]
fn valid_empty_history() {
    StreamTest {
        cases: vec![Test::single(block(1))],
        ..StreamTest::default()
    }
    .run()
}

#[test]
fn valid_blocks() {
    StreamTest {
        cases: vec![
            Test::single(block(1)),
            Test::single(block(2)),
            Test::single(block(3)),
            Test::single(block(4)),
        ],
        ..StreamTest::default()
    }
    .run()
}

#[test]
fn valid_same_block() {
    let block = block(100);
    StreamTest {
        cases: vec![
            Test::single(block.clone()),
            Test::single(block).expect_same_data(),
        ],
        ..StreamTest::default()
    }
    .run()
}

#[test]
fn valid_same_slot_different_validator() {
    StreamTest {
        registered_validators: vec![pubkey(0), pubkey(1)],
        cases: vec![
            Test::with_pubkey(pubkey(0), block(100)),
            Test::with_pubkey(pubkey(1), block(100)),
        ],
    }
    .run()
}

#[test]
fn valid_same_block_different_validator() {
    let block = block(100);
    StreamTest {
        registered_validators: vec![pubkey(0), pubkey(1)],
        cases: vec![
            Test::with_pubkey(pubkey(0), block.clone()),
            Test::with_pubkey(pubkey(1), block),
        ],
    }
    .run()
}

#[test]
fn invalid_double_block_proposal() {
    let first_block = block(1);
    StreamTest {
        cases: vec![
            Test::single(first_block.clone()),
            Test::single(block(1)).expect_invalid_block(InvalidBlock::DoubleBlockProposal(
                SignedBlock::from_header(&first_block, DEFAULT_DOMAIN),
            )),
        ],
        ..StreamTest::default()
    }
    .run()
}

#[test]
fn invalid_double_block_proposal_diff_domain() {
    let first_block = block(1);
    let domain1 = Hash256::from_low_u64_be(1);
    let domain2 = Hash256::from_low_u64_be(2);
    StreamTest {
        cases: vec![
            Test::single(first_block.clone()).with_domain(domain1),
            Test::single(first_block.clone())
                .with_domain(domain2)
                .expect_invalid_block(InvalidBlock::DoubleBlockProposal(SignedBlock::from_header(
                    &first_block,
                    domain1,
                ))),
        ],
        ..StreamTest::default()
    }
    .run()
}

#[test]
fn invalid_unregistered_validator() {
    StreamTest {
        registered_validators: vec![],
        cases: vec![
            Test::single(block(0)).expect_result(Err(NotSafe::UnregisteredValidator(pubkey(
                DEFAULT_VALIDATOR_INDEX,
            )))),
        ],
    }
    .run()
}
