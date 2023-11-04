use super::*;

pub fn get_execution_status_test_definition_01() -> ForkChoiceTestDefinition {
    let balances = vec![1; 2];
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

    ops.push(Operation::AssertWeight {
        block_root: get_root(0),
        weight: 1,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(1),
        weight: 1,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(2),
        weight: 0,
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

    ops.push(Operation::AssertWeight {
        block_root: get_root(0),
        weight: 2,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(1),
        weight: 1,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(2),
        weight: 1,
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

    ops.push(Operation::AssertWeight {
        block_root: get_root(0),
        weight: 2,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(1),
        weight: 1,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(2),
        weight: 1,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(3),
        weight: 0,
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

    ops.push(Operation::AssertWeight {
        block_root: get_root(0),
        weight: 2,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(1),
        weight: 1,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(2),
        weight: 1,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(3),
        weight: 1,
    });

    // Invalidate the payload of 3.
    //
    //          0
    //         / \
    //        2   1
    //            |
    //            3 <- INVALID
    ops.push(Operation::InvalidatePayload {
        head_block_root: get_root(3),
        latest_valid_ancestor_root: Some(get_hash(1)),
    });

    // Ensure that the head is still 2.
    //
    //          0
    //         / \
    // head-> 2   1
    //            |
    //            3 <- INVALID
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

    // Invalidation of 3 should have removed upstream weight.
    ops.push(Operation::AssertWeight {
        block_root: get_root(0),
        weight: 1,
    });
    // Invalidation of 3 should have removed upstream weight.
    ops.push(Operation::AssertWeight {
        block_root: get_root(1),
        weight: 0,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(2),
        weight: 1,
    });
    // Invalidation should have removed weight.
    ops.push(Operation::AssertWeight {
        block_root: get_root(3),
        weight: 0,
    });

    // Move a vote from 2 to 1. This is slashable, but that's not relevant here.
    //
    //           0
    //          / \
    // -vote-> 2   1 <- +vote
    //             |
    //             3 <- INVALID
    ops.push(Operation::ProcessAttestation {
        validator_index: 1,
        block_root: get_root(1),
        target_epoch: Epoch::new(3),
    });

    // Ensure that the head has switched back to 1
    //
    //          0
    //         / \
    //        2   1 <-head
    //            |
    //            3 <- INVALID
    ops.push(Operation::FindHead {
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        justified_state_balances: balances,
        expected_head: get_root(1),
    });

    ops.push(Operation::AssertWeight {
        block_root: get_root(0),
        weight: 1,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(1),
        weight: 1,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(2),
        weight: 0,
    });
    // Invalidation should have removed weight.
    ops.push(Operation::AssertWeight {
        block_root: get_root(3),
        weight: 0,
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

pub fn get_execution_status_test_definition_02() -> ForkChoiceTestDefinition {
    let balances = vec![1; 2];
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

    ops.push(Operation::AssertWeight {
        block_root: get_root(0),
        weight: 1,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(1),
        weight: 1,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(2),
        weight: 0,
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

    ops.push(Operation::AssertWeight {
        block_root: get_root(0),
        weight: 2,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(1),
        weight: 1,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(2),
        weight: 1,
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

    ops.push(Operation::AssertWeight {
        block_root: get_root(0),
        weight: 2,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(1),
        weight: 1,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(2),
        weight: 1,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(3),
        weight: 0,
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

    // Move validator #1 vote from 2 to 3
    //
    //          0
    //         / \
    // -vote->2   1
    //            |
    //            3 <- +vote
    ops.push(Operation::ProcessAttestation {
        validator_index: 1,
        block_root: get_root(3),
        target_epoch: Epoch::new(3),
    });

    // Ensure that the head is now 3.
    //
    //          0
    //         / \
    //        2   1
    //            |
    //            3 <-head
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

    ops.push(Operation::AssertWeight {
        block_root: get_root(0),
        weight: 2,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(1),
        weight: 2,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(2),
        weight: 0,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(3),
        weight: 2,
    });

    // Invalidate the payload of 3.
    //
    //          0
    //         / \
    //        2   1
    //            |
    //            3 <- INVALID
    ops.push(Operation::InvalidatePayload {
        head_block_root: get_root(3),
        latest_valid_ancestor_root: Some(get_hash(1)),
    });

    // Ensure that the head is now 2.
    //
    //          0
    //         / \
    // head-> 2   1
    //            |
    //            3 <- INVALID
    ops.push(Operation::FindHead {
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        justified_state_balances: balances,
        expected_head: get_root(2),
    });

    // Invalidation of 3 should have removed upstream weight.
    ops.push(Operation::AssertWeight {
        block_root: get_root(0),
        weight: 0,
    });
    // Invalidation of 3 should have removed upstream weight.
    ops.push(Operation::AssertWeight {
        block_root: get_root(1),
        weight: 0,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(2),
        weight: 0,
    });
    // Invalidation should have removed weight.
    ops.push(Operation::AssertWeight {
        block_root: get_root(3),
        weight: 0,
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

pub fn get_execution_status_test_definition_03() -> ForkChoiceTestDefinition {
    let balances = vec![1_000; 2_000];
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

    ops.push(Operation::AssertWeight {
        block_root: get_root(0),
        weight: 1_000,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(1),
        weight: 1_000,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(2),
        weight: 0,
    });

    // Add another vote to 1
    //
    //           0
    //          / \
    //         2   1 <- +vote
    ops.push(Operation::ProcessAttestation {
        validator_index: 1,
        block_root: get_root(1),
        target_epoch: Epoch::new(2),
    });

    // Ensure that the head is 1.
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

    ops.push(Operation::AssertWeight {
        block_root: get_root(0),
        weight: 2_000,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(1),
        weight: 2_000,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(2),
        weight: 0,
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

    // Ensure that the head is now 3, applying a proposer boost to 3 as well.
    //
    //          0
    //         / \
    //        2   1
    //            |
    //            3 <- head
    ops.push(Operation::ProposerBoostFindHead {
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
        proposer_boost_root: get_root(3),
    });

    ops.push(Operation::AssertWeight {
        block_root: get_root(0),
        weight: 33_250,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(1),
        weight: 33_250,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(2),
        weight: 0,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(3),
        // This is a "magic number" generated from `calculate_committee_fraction`.
        weight: 31_250,
    });

    // Invalidate the payload of 3.
    //
    //          0
    //         / \
    //        2   1
    //            |
    //            3 <- INVALID
    ops.push(Operation::InvalidatePayload {
        head_block_root: get_root(3),
        latest_valid_ancestor_root: Some(get_hash(1)),
    });

    // Ensure that the head is now 1, maintaining the proposer boost on the invalid block.
    //
    //          0
    //         / \
    //        2   1 <- head
    //            |
    //            3 <- INVALID
    ops.push(Operation::ProposerBoostFindHead {
        justified_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        finalized_checkpoint: Checkpoint {
            epoch: Epoch::new(1),
            root: get_root(0),
        },
        justified_state_balances: balances,
        expected_head: get_root(1),
        proposer_boost_root: get_root(3),
    });

    ops.push(Operation::AssertWeight {
        block_root: get_root(0),
        weight: 2_000,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(1),
        weight: 2_000,
    });
    ops.push(Operation::AssertWeight {
        block_root: get_root(2),
        weight: 0,
    });
    // The proposer boost should be reverted due to the invalid payload.
    ops.push(Operation::AssertWeight {
        block_root: get_root(3),
        weight: 0,
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
    fn test_01() {
        let test = get_execution_status_test_definition_01();
        test.run();
    }

    #[test]
    fn test_02() {
        let test = get_execution_status_test_definition_02();
        test.run();
    }

    #[test]
    fn test_03() {
        let test = get_execution_status_test_definition_03();
        test.run();
    }
}
