use super::*;

pub fn get_votes_test_definition() -> ForkChoiceTestDefinition {
    let mut balances = vec![1; 2];
    let mut ops = vec![];

    // Ensure that the head starts at the finalized block.
    ops.push(Operation::FindHead {
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        justified_state_balances: balances.clone(),
        expected_head: get_root(0),
    });

    // Add a block with a hash of 2.
    //
    //          0
    //         /
    //        2
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(1),
        root: get_root(2),
        parent_root: get_root(0),
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
    });

    // Ensure that the head is 2
    //
    //          0
    //         /
    // head-> 2
    ops.push(Operation::FindHead {
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        justified_state_balances: balances.clone(),
        expected_head: get_root(2),
    });

    // Add a block with a hash of 1 that comes off the genesis block (this is a fork compared
    // to the previous block).
    //
    //          0
    //         / \
    //        2   1
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(1),
        root: get_root(1),
        parent_root: get_root(0),
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
    });

    // Ensure that the head is still 2
    //
    //          0
    //         / \
    // head-> 2   1
    ops.push(Operation::FindHead {
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        justified_state_balances: balances.clone(),
        expected_head: get_root(2),
    });

    // Add a vote to block 1
    //
    //          0
    //         / \
    //        2   1 <- +vote
    ops.push(Operation::ProcessAttestation {
        validator_index: 0,
        block_root: get_root(1),
        target_epoch: Epoch::new(2),
    });

    // Ensure that the head is now 1, because 1 has a vote.
    //
    //          0
    //         / \
    //        2   1 <- head
    ops.push(Operation::FindHead {
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        justified_state_balances: balances.clone(),
        expected_head: get_root(1),
    });

    // Add a vote to block 2
    //
    //           0
    //          / \
    // +vote-> 2   1
    ops.push(Operation::ProcessAttestation {
        validator_index: 1,
        block_root: get_root(2),
        target_epoch: Epoch::new(2),
    });

    // Ensure that the head is 2 since 1 and 2 both have a vote
    //
    //          0
    //         / \
    // head-> 2   1
    ops.push(Operation::FindHead {
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        justified_state_balances: balances.clone(),
        expected_head: get_root(2),
    });

    // Add block 3.
    //
    //          0
    //         / \
    //        2   1
    //            |
    //            3
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(2),
        root: get_root(3),
        parent_root: get_root(1),
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
    });

    // Ensure that the head is still 2
    //
    //          0
    //         / \
    // head-> 2   1
    //            |
    //            3
    ops.push(Operation::FindHead {
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        justified_state_balances: balances.clone(),
        expected_head: get_root(2),
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
        block_root: get_root(3),
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
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        justified_state_balances: balances.clone(),
        expected_head: get_root(2),
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
        block_root: get_root(1),
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
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        justified_state_balances: balances.clone(),
        expected_head: get_root(3),
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
        slot: Slot::new(3),
        root: get_root(4),
        parent_root: get_root(3),
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
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
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        justified_state_balances: balances.clone(),
        expected_head: get_root(4),
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
        slot: Slot::new(4),
        root: get_root(5),
        parent_root: get_root(4),
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(1),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(1),
        },
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
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        justified_state_balances: balances.clone(),
        expected_head: get_root(4),
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
        root: get_root(6),
        parent_root: get_root(4),
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
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
        block_root: get_root(5),
        target_epoch: Epoch::new(4),
    });
    ops.push(Operation::ProcessAttestation {
        validator_index: 1,
        block_root: get_root(5),
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
        root: get_root(7),
        parent_root: get_root(5),
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
    });
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(0),
        root: get_root(8),
        parent_root: get_root(7),
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
    });
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(0),
        root: get_root(9),
        parent_root: get_root(8),
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
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
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        justified_state_balances: balances.clone(),
        expected_head: get_root(6),
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
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
        justified_state_balances: balances.clone(),
        expected_head: get_root(9),
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
        block_root: get_root(9),
        target_epoch: Epoch::new(5),
    });
    ops.push(Operation::ProcessAttestation {
        validator_index: 1,
        block_root: get_root(9),
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
        root: get_root(10),
        parent_root: get_root(8),
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
    });

    // Double-check the head is still 9 (no diagram this time)
    ops.push(Operation::FindHead {
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
        justified_state_balances: balances.clone(),
        expected_head: get_root(9),
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
        block_root: get_root(10),
        target_epoch: Epoch::new(5),
    });
    ops.push(Operation::ProcessAttestation {
        validator_index: 3,
        block_root: get_root(10),
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
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
        justified_state_balances: balances.clone(),
        expected_head: get_root(10),
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
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
        justified_state_balances: balances.clone(),
        expected_head: get_root(9),
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
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
        justified_state_balances: balances.clone(),
        expected_head: get_root(10),
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
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
        justified_state_balances: balances.clone(),
        expected_head: get_root(9),
    });

    // Ensure that pruning below the prune threshold does not prune.
    ops.push(Operation::Prune {
        finalized_root: get_root(5),
        prune_threshold: usize::MAX,
        expected_len: 11,
    });

    // Run find-head, ensure the no-op prune didn't change the head.
    ops.push(Operation::FindHead {
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
        justified_state_balances: balances.clone(),
        expected_head: get_root(9),
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
        finalized_root: get_root(5),
        prune_threshold: 1,
        expected_len: 6,
    });

    // Run find-head, ensure the prune didn't change the head.
    ops.push(Operation::FindHead {
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
        justified_state_balances: balances.clone(),
        expected_head: get_root(9),
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
        root: get_root(11),
        parent_root: get_root(9),
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
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
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(2),
            root: get_root(5),
        },
        justified_state_balances: balances,
        expected_head: get_root(11),
    });

    ForkChoiceTestDefinition {
        finalized_block_slot: Slot::new(0),
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        operations: ops,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        let test = get_votes_test_definition();
        test.run();
    }
}
