use crate::ProtoArrayForkChoice;
use types::{Epoch, Hash256, Slot};

#[derive(Debug, Clone)]
pub enum Operation {
    FindHead {
        justified_epoch: Epoch,
        justified_root: Hash256,
        finalized_epoch: Epoch,
        justified_state_balances: Vec<u64>,
        expected_head: Hash256,
    },
    InvalidFindHead {
        justified_epoch: Epoch,
        justified_root: Hash256,
        finalized_epoch: Epoch,
        justified_state_balances: Vec<u64>,
    },
    ProcessBlock {
        slot: Slot,
        root: Hash256,
        parent_root: Hash256,
        justified_epoch: Epoch,
        finalized_epoch: Epoch,
    },
    ProcessAttestation {
        validator_index: usize,
        block_root: Hash256,
        target_epoch: Epoch,
    },
    Prune {
        finalized_epoch: Epoch,
        finalized_root: Hash256,
        prune_threshold: usize,
        expected_len: usize,
    },
}

pub struct ForkChoiceTestDefinition {
    pub finalized_block_slot: Slot,
    pub justified_epoch: Epoch,
    pub finalized_epoch: Epoch,
    pub finalized_root: Hash256,
    pub operations: Vec<Operation>,
}

impl ForkChoiceTestDefinition {
    pub fn run(self) {
        let fork_choice = ProtoArrayForkChoice::new(
            self.finalized_block_slot,
            self.justified_epoch,
            self.finalized_epoch,
            self.finalized_root,
        )
        .expect("should create fork choice struct");

        for (op_index, op) in self.operations.into_iter().enumerate() {
            match op.clone() {
                Operation::FindHead {
                    justified_epoch,
                    justified_root,
                    finalized_epoch,
                    justified_state_balances,
                    expected_head,
                } => {
                    let head = fork_choice
                        .find_head(
                            justified_epoch,
                            justified_root,
                            finalized_epoch,
                            &justified_state_balances,
                        )
                        .expect(&format!(
                            "find_head op at index {} returned error",
                            op_index
                        ));

                    assert_eq!(
                        head, expected_head,
                        "Operation at index {} failed checks. Operation: {:?}",
                        op_index, op
                    );
                    check_bytes_round_trip(&fork_choice);
                }
                Operation::InvalidFindHead {
                    justified_epoch,
                    justified_root,
                    finalized_epoch,
                    justified_state_balances,
                } => {
                    let result = fork_choice.find_head(
                        justified_epoch,
                        justified_root,
                        finalized_epoch,
                        &justified_state_balances,
                    );

                    assert!(
                        result.is_err(),
                        "Operation at index {} . Operation: {:?}",
                        op_index,
                        op
                    );
                    check_bytes_round_trip(&fork_choice);
                }
                Operation::ProcessBlock {
                    slot,
                    root,
                    parent_root,
                    justified_epoch,
                    finalized_epoch,
                } => {
                    fork_choice
                        .process_block(slot, root, parent_root, justified_epoch, finalized_epoch)
                        .expect(&format!(
                            "process_block op at index {} returned error",
                            op_index
                        ));
                    check_bytes_round_trip(&fork_choice);
                }
                Operation::ProcessAttestation {
                    validator_index,
                    block_root,
                    target_epoch,
                } => {
                    fork_choice
                        .process_attestation(validator_index, block_root, target_epoch)
                        .expect(&format!(
                            "process_attestation op at index {} returned error",
                            op_index
                        ));
                    check_bytes_round_trip(&fork_choice);
                }
                Operation::Prune {
                    finalized_epoch,
                    finalized_root,
                    prune_threshold,
                    expected_len,
                } => {
                    fork_choice.set_prune_threshold(prune_threshold);
                    fork_choice
                        .update_finalized_root(finalized_epoch, finalized_root)
                        .expect("update_finalized_root op at index {} returned error");

                    // Ensure that no pruning happened.
                    assert_eq!(
                        fork_choice.len(),
                        expected_len,
                        "Prune op at index {} failed with {} instead of {}",
                        op_index,
                        fork_choice.len(),
                        expected_len
                    );
                }
            }
        }
    }
}

/// Gives a hash that is not the zero hash (unless i is `usize::max_value)`.
fn get_hash(i: u64) -> Hash256 {
    Hash256::from_low_u64_be(i)
}

fn check_bytes_round_trip(original: &ProtoArrayForkChoice) {
    let bytes = original.as_bytes();
    let decoded =
        ProtoArrayForkChoice::from_bytes(&bytes).expect("fork choice should decode from bytes");
    assert!(
        *original == decoded,
        "fork choice should encode and decode without change"
    );
}

pub fn get_no_votes_test_definition() -> ForkChoiceTestDefinition {
    let balances = vec![0; 16];

    let operations = vec![
        // Check that the head is the finalized block.
        Operation::FindHead {
            justified_epoch: Epoch::new(1),
            justified_root: Hash256::zero(),
            finalized_epoch: Epoch::new(1),
            justified_state_balances: balances.clone(),
            expected_head: Hash256::zero(),
        },
        // Add block 2
        //
        //         0
        //        /
        //        2
        Operation::ProcessBlock {
            slot: Slot::new(0),
            root: get_hash(2),
            parent_root: get_hash(0),
            justified_epoch: Epoch::new(1),
            finalized_epoch: Epoch::new(1),
        },
        // Ensure the head is 2
        //
        //         0
        //        /
        //        2 <- head
        Operation::FindHead {
            justified_epoch: Epoch::new(1),
            justified_root: Hash256::zero(),
            finalized_epoch: Epoch::new(1),
            justified_state_balances: balances.clone(),
            expected_head: get_hash(2),
        },
        // Add block 1
        //
        //         0
        //        / \
        //        2  1
        Operation::ProcessBlock {
            slot: Slot::new(0),
            root: get_hash(1),
            parent_root: get_hash(0),
            justified_epoch: Epoch::new(1),
            finalized_epoch: Epoch::new(1),
        },
        // Ensure the head is still 2
        //
        //         0
        //        / \
        // head-> 2  1
        Operation::FindHead {
            justified_epoch: Epoch::new(1),
            justified_root: Hash256::zero(),
            finalized_epoch: Epoch::new(1),
            justified_state_balances: balances.clone(),
            expected_head: get_hash(2),
        },
        // Add block 3
        //
        //         0
        //        / \
        //        2  1
        //           |
        //           3
        Operation::ProcessBlock {
            slot: Slot::new(0),
            root: get_hash(3),
            parent_root: get_hash(1),
            justified_epoch: Epoch::new(1),
            finalized_epoch: Epoch::new(1),
        },
        // Ensure 2 is still the head
        //
        //          0
        //         / \
        // head-> 2  1
        //           |
        //           3
        Operation::FindHead {
            justified_epoch: Epoch::new(1),
            justified_root: Hash256::zero(),
            finalized_epoch: Epoch::new(1),
            justified_state_balances: balances.clone(),
            expected_head: get_hash(2),
        },
        // Add block 4
        //
        //         0
        //        / \
        //        2  1
        //        |  |
        //        4  3
        Operation::ProcessBlock {
            slot: Slot::new(0),
            root: get_hash(4),
            parent_root: get_hash(2),
            justified_epoch: Epoch::new(1),
            finalized_epoch: Epoch::new(1),
        },
        // Ensure the head is 4.
        //
        //         0
        //        / \
        //        2  1
        //        |  |
        // head-> 4  3
        Operation::FindHead {
            justified_epoch: Epoch::new(1),
            justified_root: Hash256::zero(),
            finalized_epoch: Epoch::new(1),
            justified_state_balances: balances.clone(),
            expected_head: get_hash(4),
        },
        // Add block 5 with a justified epoch of 2
        //
        //         0
        //        / \
        //        2  1
        //        |  |
        //        4  3
        //        |
        //        5 <- justified epoch = 2
        Operation::ProcessBlock {
            slot: Slot::new(0),
            root: get_hash(5),
            parent_root: get_hash(4),
            justified_epoch: Epoch::new(2),
            finalized_epoch: Epoch::new(1),
        },
        // Ensure the head is still 4 whilst the justified epoch is 0.
        //
        //         0
        //        / \
        //        2  1
        //        |  |
        // head-> 4  3
        //        |
        //        5
        Operation::FindHead {
            justified_epoch: Epoch::new(1),
            justified_root: Hash256::zero(),
            finalized_epoch: Epoch::new(1),
            justified_state_balances: balances.clone(),
            expected_head: get_hash(4),
        },
        // Ensure there is an error when starting from a block that has the wrong justified epoch.
        //
        //      0
        //     / \
        //     2  1
        //     |  |
        //     4  3
        //     |
        //     5 <- starting from 5 with justified epoch 0 should error.
        Operation::InvalidFindHead {
            justified_epoch: Epoch::new(1),
            justified_root: get_hash(5),
            finalized_epoch: Epoch::new(1),
            justified_state_balances: balances.clone(),
        },
        // Set the justified epoch to 2 and the start block to 5 and ensure 5 is the head.
        //
        //      0
        //     / \
        //     2  1
        //     |  |
        //     4  3
        //     |
        //     5 <- head
        Operation::FindHead {
            justified_epoch: Epoch::new(2),
            justified_root: get_hash(5),
            finalized_epoch: Epoch::new(1),
            justified_state_balances: balances.clone(),
            expected_head: get_hash(5),
        },
        // Add block 6
        //
        //      0
        //     / \
        //     2  1
        //     |  |
        //     4  3
        //     |
        //     5
        //     |
        //     6
        Operation::ProcessBlock {
            slot: Slot::new(0),
            root: get_hash(6),
            parent_root: get_hash(5),
            justified_epoch: Epoch::new(2),
            finalized_epoch: Epoch::new(1),
        },
        // Ensure 6 is the head
        //
        //      0
        //     / \
        //     2  1
        //     |  |
        //     4  3
        //     |
        //     5
        //     |
        //     6 <- head
        Operation::FindHead {
            justified_epoch: Epoch::new(2),
            justified_root: get_hash(5),
            finalized_epoch: Epoch::new(1),
            justified_state_balances: balances.clone(),
            expected_head: get_hash(6),
        },
    ];

    ForkChoiceTestDefinition {
        finalized_block_slot: Slot::new(0),
        justified_epoch: Epoch::new(1),
        finalized_epoch: Epoch::new(1),
        finalized_root: get_hash(0),
        operations,
    }
}

pub fn get_votes_test_definition() -> ForkChoiceTestDefinition {
    let mut balances = vec![1; 2];
    let mut ops = vec![];

    // Ensure that the head starts at the finalized block.
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(1),
        justified_root: get_hash(0),
        finalized_epoch: Epoch::new(1),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(0),
    });

    // Add a block with a hash of 2.
    //
    //          0
    //         /
    //        2
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(0),
        root: get_hash(2),
        parent_root: get_hash(0),
        justified_epoch: Epoch::new(1),
        finalized_epoch: Epoch::new(1),
    });

    // Ensure that the head is 2
    //
    //          0
    //         /
    // head-> 2
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(1),
        justified_root: get_hash(0),
        finalized_epoch: Epoch::new(1),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(2),
    });

    // Add a block with a hash of 1 that comes off the genesis block (this is a fork compared
    // to the previous block).
    //
    //          0
    //         / \
    //        2   1
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(0),
        root: get_hash(1),
        parent_root: get_hash(0),
        justified_epoch: Epoch::new(1),
        finalized_epoch: Epoch::new(1),
    });

    // Ensure that the head is still 2
    //
    //          0
    //         / \
    // head-> 2   1
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(1),
        justified_root: get_hash(0),
        finalized_epoch: Epoch::new(1),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(2),
    });

    // Add a vote to block 1
    //
    //          0
    //         / \
    //        2   1 <- +vote
    ops.push(Operation::ProcessAttestation {
        validator_index: 0,
        block_root: get_hash(1),
        target_epoch: Epoch::new(2),
    });

    // Ensure that the head is now 1, beacuse 1 has a vote.
    //
    //          0
    //         / \
    //        2   1 <- head
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(1),
        justified_root: get_hash(0),
        finalized_epoch: Epoch::new(1),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(1),
    });

    // Add a vote to block 2
    //
    //           0
    //          / \
    // +vote-> 2   1
    ops.push(Operation::ProcessAttestation {
        validator_index: 1,
        block_root: get_hash(2),
        target_epoch: Epoch::new(2),
    });

    // Ensure that the head is 2 since 1 and 2 both have a vote
    //
    //          0
    //         / \
    // head-> 2   1
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(1),
        justified_root: get_hash(0),
        finalized_epoch: Epoch::new(1),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(2),
    });

    // Add block 3.
    //
    //          0
    //         / \
    //        2   1
    //            |
    //            3
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(0),
        root: get_hash(3),
        parent_root: get_hash(1),
        justified_epoch: Epoch::new(1),
        finalized_epoch: Epoch::new(1),
    });

    // Ensure that the head is still 2
    //
    //          0
    //         / \
    // head-> 2   1
    //            |
    //            3
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(1),
        justified_root: get_hash(0),
        finalized_epoch: Epoch::new(1),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(2),
    });

    // Move validator #0 vote from 1 to 3
    //
    //          0
    //         / \
    //        2   1 <- -vote
    //            |
    //            3 <- +vote
    ops.push(Operation::ProcessAttestation {
        validator_index: 0,
        block_root: get_hash(3),
        target_epoch: Epoch::new(3),
    });

    // Ensure that the head is still 2
    //
    //          0
    //         / \
    // head-> 2   1
    //            |
    //            3
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(1),
        justified_root: get_hash(0),
        finalized_epoch: Epoch::new(1),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(2),
    });

    // Move validator #1 vote from 2 to 1 (this is an equivocation, but fork choice doesn't
    // care)
    //
    //           0
    //          / \
    // -vote-> 2   1 <- +vote
    //             |
    //             3
    ops.push(Operation::ProcessAttestation {
        validator_index: 1,
        block_root: get_hash(1),
        target_epoch: Epoch::new(3),
    });

    // Ensure that the head is now 3
    //
    //          0
    //         / \
    //        2   1
    //            |
    //            3 <- head
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(1),
        justified_root: get_hash(0),
        finalized_epoch: Epoch::new(1),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(3),
    });

    // Add block 4.
    //
    //          0
    //         / \
    //        2   1
    //            |
    //            3
    //            |
    //            4
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(0),
        root: get_hash(4),
        parent_root: get_hash(3),
        justified_epoch: Epoch::new(1),
        finalized_epoch: Epoch::new(1),
    });

    // Ensure that the head is now 4
    //
    //          0
    //         / \
    //        2   1
    //            |
    //            3
    //            |
    //            4 <- head
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(1),
        justified_root: get_hash(0),
        finalized_epoch: Epoch::new(1),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(4),
    });

    // Add block 5, which has a justified epoch of 2.
    //
    //          0
    //         / \
    //        2   1
    //            |
    //            3
    //            |
    //            4
    //           /
    //          5 <- justified epoch = 2
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(0),
        root: get_hash(5),
        parent_root: get_hash(4),
        justified_epoch: Epoch::new(2),
        finalized_epoch: Epoch::new(2),
    });

    // Ensure that 5 is filtered out and the head stays at 4.
    //
    //          0
    //         / \
    //        2   1
    //            |
    //            3
    //            |
    //            4 <- head
    //           /
    //          5
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(1),
        justified_root: get_hash(0),
        finalized_epoch: Epoch::new(1),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(4),
    });

    // Add block 6, which has a justified epoch of 0.
    //
    //          0
    //         / \
    //        2   1
    //            |
    //            3
    //            |
    //            4
    //           / \
    //          5   6 <- justified epoch = 0
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(0),
        root: get_hash(6),
        parent_root: get_hash(4),
        justified_epoch: Epoch::new(1),
        finalized_epoch: Epoch::new(1),
    });

    // Move both votes to 5.
    //
    //           0
    //          / \
    //         2   1
    //             |
    //             3
    //             |
    //             4
    //            / \
    // +2 vote-> 5   6
    ops.push(Operation::ProcessAttestation {
        validator_index: 0,
        block_root: get_hash(5),
        target_epoch: Epoch::new(4),
    });
    ops.push(Operation::ProcessAttestation {
        validator_index: 1,
        block_root: get_hash(5),
        target_epoch: Epoch::new(4),
    });

    // Add blocks 7, 8 and 9. Adding these blocks helps test the `best_descendant`
    // functionality.
    //
    //          0
    //         / \
    //        2   1
    //            |
    //            3
    //            |
    //            4
    //           / \
    //          5   6
    //          |
    //          7
    //          |
    //          8
    //         /
    //         9
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(0),
        root: get_hash(7),
        parent_root: get_hash(5),
        justified_epoch: Epoch::new(2),
        finalized_epoch: Epoch::new(2),
    });
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(0),
        root: get_hash(8),
        parent_root: get_hash(7),
        justified_epoch: Epoch::new(2),
        finalized_epoch: Epoch::new(2),
    });
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(0),
        root: get_hash(9),
        parent_root: get_hash(8),
        justified_epoch: Epoch::new(2),
        finalized_epoch: Epoch::new(2),
    });

    // Ensure that 6 is the head, even though 5 has all the votes. This is testing to ensure
    // that 5 is filtered out due to a differing justified epoch.
    //
    //          0
    //         / \
    //        2   1
    //            |
    //            3
    //            |
    //            4
    //           / \
    //          5   6 <- head
    //          |
    //          7
    //          |
    //          8
    //         /
    //         9
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(1),
        justified_root: get_hash(0),
        finalized_epoch: Epoch::new(1),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(6),
    });

    // Change fork-choice justified epoch to 1, and the start block to 5 and ensure that 9 is
    // the head.
    //
    // << Change justified epoch to 1 >>
    //
    //          0
    //         / \
    //        2   1
    //            |
    //            3
    //            |
    //            4
    //           / \
    //          5   6
    //          |
    //          7
    //          |
    //          8
    //         /
    // head-> 9
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(2),
        justified_root: get_hash(5),
        finalized_epoch: Epoch::new(2),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(9),
    });

    // Change fork-choice justified epoch to 1, and the start block to 5 and ensure that 9 is
    // the head.
    //
    // << Change justified epoch to 1 >>
    //
    //          0
    //         / \
    //        2   1
    //            |
    //            3
    //            |
    //            4
    //           / \
    //          5   6
    //          |
    //          7
    //          |
    //          8
    //         /
    //        9 <- +2 votes
    ops.push(Operation::ProcessAttestation {
        validator_index: 0,
        block_root: get_hash(9),
        target_epoch: Epoch::new(5),
    });
    ops.push(Operation::ProcessAttestation {
        validator_index: 1,
        block_root: get_hash(9),
        target_epoch: Epoch::new(5),
    });

    // Add block 10
    //
    //          0
    //         / \
    //        2   1
    //            |
    //            3
    //            |
    //            4
    //           / \
    //          5   6
    //          |
    //          7
    //          |
    //          8
    //         / \
    //        9  10
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(0),
        root: get_hash(10),
        parent_root: get_hash(8),
        justified_epoch: Epoch::new(2),
        finalized_epoch: Epoch::new(2),
    });

    // Double-check the head is still 9 (no diagram this time)
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(2),
        justified_root: get_hash(5),
        finalized_epoch: Epoch::new(2),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(9),
    });

    // Introduce 2 more validators into the system
    balances = vec![1; 4];

    // Have the two new validators vote for 10
    //
    //          0
    //         / \
    //        2   1
    //            |
    //            3
    //            |
    //            4
    //           / \
    //          5   6
    //          |
    //          7
    //          |
    //          8
    //         / \
    //        9  10 <- +2 votes
    ops.push(Operation::ProcessAttestation {
        validator_index: 2,
        block_root: get_hash(10),
        target_epoch: Epoch::new(5),
    });
    ops.push(Operation::ProcessAttestation {
        validator_index: 3,
        block_root: get_hash(10),
        target_epoch: Epoch::new(5),
    });

    // Check the head is now 10.
    //
    //          0
    //         / \
    //        2   1
    //            |
    //            3
    //            |
    //            4
    //           / \
    //          5   6
    //          |
    //          7
    //          |
    //          8
    //         / \
    //        9  10 <- head
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(2),
        justified_root: get_hash(5),
        finalized_epoch: Epoch::new(2),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(10),
    });

    // Set the balances of the last two validators to zero
    balances = vec![1, 1, 0, 0];

    // Check the head is 9 again.
    //
    //          .
    //          .
    //          .
    //          |
    //          8
    //         / \
    // head-> 9  10
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(2),
        justified_root: get_hash(5),
        finalized_epoch: Epoch::new(2),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(9),
    });

    // Set the balances of the last two validators back to 1
    balances = vec![1; 4];

    // Check the head is 10.
    //
    //          .
    //          .
    //          .
    //          |
    //          8
    //         / \
    //        9  10 <- head
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(2),
        justified_root: get_hash(5),
        finalized_epoch: Epoch::new(2),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(10),
    });

    // Remove the last two validators
    balances = vec![1; 2];

    // Check the head is 9 again.
    //
    //  (prior blocks omitted for brevity)
    //          .
    //          .
    //          .
    //          |
    //          8
    //         / \
    // head-> 9  10
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(2),
        justified_root: get_hash(5),
        finalized_epoch: Epoch::new(2),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(9),
    });

    // Ensure that pruning below the prune threshold does not prune.
    ops.push(Operation::Prune {
        finalized_epoch: Epoch::new(2),
        finalized_root: get_hash(5),
        prune_threshold: usize::max_value(),
        expected_len: 11,
    });

    // Run find-head, ensure the no-op prune didn't change the head.
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(2),
        justified_root: get_hash(5),
        finalized_epoch: Epoch::new(2),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(9),
    });

    // Ensure that pruning above the prune threshold does prune.
    //
    //
    //          0
    //         / \
    //        2   1
    //            |
    //            3
    //            |
    //            4
    // -------pruned here ------
    //          5   6
    //          |
    //          7
    //          |
    //          8
    //         / \
    //        9  10
    ops.push(Operation::Prune {
        finalized_epoch: Epoch::new(2),
        finalized_root: get_hash(5),
        prune_threshold: 1,
        expected_len: 6,
    });

    // Run find-head, ensure the prune didn't change the head.
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(2),
        justified_root: get_hash(5),
        finalized_epoch: Epoch::new(2),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(9),
    });

    // Add block 11
    //
    //          5   6
    //          |
    //          7
    //          |
    //          8
    //         / \
    //        9  10
    //        |
    //        11
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(0),
        root: get_hash(11),
        parent_root: get_hash(9),
        justified_epoch: Epoch::new(2),
        finalized_epoch: Epoch::new(2),
    });

    // Ensure the head is now 11
    //
    //          5   6
    //          |
    //          7
    //          |
    //          8
    //         / \
    //        9  10
    //        |
    // head-> 11
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(2),
        justified_root: get_hash(5),
        finalized_epoch: Epoch::new(2),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(11),
    });

    ForkChoiceTestDefinition {
        finalized_block_slot: Slot::new(0),
        justified_epoch: Epoch::new(1),
        finalized_epoch: Epoch::new(1),
        finalized_root: get_hash(0),
        operations: ops,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_votes() {
        let test = get_no_votes_test_definition();
        test.run();
    }

    #[test]
    fn votes() {
        let test = get_votes_test_definition();
        test.run();
    }
}
