use super::*;

pub fn get_ffg_case_01_test_definition() -> ForkChoiceTestDefinition {
    let balances = vec![1; 2];
    let mut ops = vec![];

    // Ensure that the head starts at the finalized block.
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(0),
        justified_root: get_hash(0),
        finalized_epoch: Epoch::new(0),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(0),
    });

    // Build the following tree (stick? lol).
    //
    //            0 <- just: 0, fin: 0
    //            |
    //            1 <- just: 0, fin: 0
    //            |
    //            2 <- just: 1, fin: 0
    //            |
    //            3 <- just: 2, fin: 1
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(1),
        root: get_hash(1),
        parent_root: get_hash(0),
        justified_epoch: Epoch::new(0),
        finalized_epoch: Epoch::new(0),
    });
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(2),
        root: get_hash(2),
        parent_root: get_hash(1),
        justified_epoch: Epoch::new(1),
        finalized_epoch: Epoch::new(0),
    });
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(3),
        root: get_hash(3),
        parent_root: get_hash(2),
        justified_epoch: Epoch::new(2),
        finalized_epoch: Epoch::new(1),
    });

    // Ensure that with justified epoch 0 we find 3
    //
    //            0 <- start
    //            |
    //            1
    //            |
    //            2
    //            |
    //            3 <- head
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(0),
        justified_root: get_hash(0),
        finalized_epoch: Epoch::new(0),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(3),
    });

    // Ensure that with justified epoch 1 we find 2
    //
    //            0
    //            |
    //            1
    //            |
    //            2 <- start
    //            |
    //            3 <- head
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(1),
        justified_root: get_hash(2),
        finalized_epoch: Epoch::new(0),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(2),
    });

    // Ensure that with justified epoch 2 we find 3
    //
    //            0
    //            |
    //            1
    //            |
    //            2
    //            |
    //            3 <- start + head
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(2),
        justified_root: get_hash(3),
        finalized_epoch: Epoch::new(1),
        justified_state_balances: balances,
        expected_head: get_hash(3),
    });

    // END OF TESTS
    ForkChoiceTestDefinition {
        finalized_block_slot: Slot::new(0),
        justified_epoch: Epoch::new(1),
        finalized_epoch: Epoch::new(1),
        finalized_root: get_hash(0),
        operations: ops,
    }
}

pub fn get_ffg_case_02_test_definition() -> ForkChoiceTestDefinition {
    let balances = vec![1; 2];
    let mut ops = vec![];

    // Ensure that the head starts at the finalized block.
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(1),
        justified_root: get_hash(0),
        finalized_epoch: Epoch::new(1),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(0),
    });

    // Build the following tree.
    //
    //                       0
    //                      / \
    //  just: 0, fin: 0 -> 1   2 <- just: 0, fin: 0
    //                     |   |
    //  just: 1, fin: 0 -> 3   4 <- just: 0, fin: 0
    //                     |   |
    //  just: 1, fin: 0 -> 5   6 <- just: 0, fin: 0
    //                     |   |
    //  just: 1, fin: 0 -> 7   8 <- just: 1, fin: 0
    //                     |   |
    //  just: 2, fin: 0 -> 9  10 <- just: 2, fin: 0

    //  Left branch
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(1),
        root: get_hash(1),
        parent_root: get_hash(0),
        justified_epoch: Epoch::new(0),
        finalized_epoch: Epoch::new(0),
    });
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(2),
        root: get_hash(3),
        parent_root: get_hash(1),
        justified_epoch: Epoch::new(1),
        finalized_epoch: Epoch::new(0),
    });
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(3),
        root: get_hash(5),
        parent_root: get_hash(3),
        justified_epoch: Epoch::new(1),
        finalized_epoch: Epoch::new(0),
    });
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(4),
        root: get_hash(7),
        parent_root: get_hash(5),
        justified_epoch: Epoch::new(1),
        finalized_epoch: Epoch::new(0),
    });
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(4),
        root: get_hash(9),
        parent_root: get_hash(7),
        justified_epoch: Epoch::new(2),
        finalized_epoch: Epoch::new(0),
    });

    //  Right branch
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(1),
        root: get_hash(2),
        parent_root: get_hash(0),
        justified_epoch: Epoch::new(0),
        finalized_epoch: Epoch::new(0),
    });
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(2),
        root: get_hash(4),
        parent_root: get_hash(2),
        justified_epoch: Epoch::new(0),
        finalized_epoch: Epoch::new(0),
    });
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(3),
        root: get_hash(6),
        parent_root: get_hash(4),
        justified_epoch: Epoch::new(0),
        finalized_epoch: Epoch::new(0),
    });
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(4),
        root: get_hash(8),
        parent_root: get_hash(6),
        justified_epoch: Epoch::new(1),
        finalized_epoch: Epoch::new(0),
    });
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(4),
        root: get_hash(10),
        parent_root: get_hash(8),
        justified_epoch: Epoch::new(2),
        finalized_epoch: Epoch::new(0),
    });

    // Ensure that if we start at 0 we find 10 (just: 0, fin: 0).
    //
    //           0  <-- start
    //          / \
    //         1   2
    //         |   |
    //         3   4
    //         |   |
    //         5   6
    //         |   |
    //         7   8
    //         |   |
    //         9  10 <-- head
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(0),
        justified_root: get_hash(0),
        finalized_epoch: Epoch::new(0),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(10),
    });
    // Same as above, but with justified epoch 2.
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(2),
        justified_root: get_hash(0),
        finalized_epoch: Epoch::new(0),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(10),
    });
    // Same as above, but with justified epoch 3 (should be invalid).
    ops.push(Operation::InvalidFindHead {
        justified_epoch: Epoch::new(3),
        justified_root: get_hash(0),
        finalized_epoch: Epoch::new(0),
        justified_state_balances: balances.clone(),
    });

    // Add a vote to 1.
    //
    //                 0
    //                / \
    //    +1 vote -> 1   2
    //               |   |
    //               3   4
    //               |   |
    //               5   6
    //               |   |
    //               7   8
    //               |   |
    //               9  10
    ops.push(Operation::ProcessAttestation {
        validator_index: 0,
        block_root: get_hash(1),
        target_epoch: Epoch::new(0),
    });

    // Ensure that if we start at 0 we find 9 (just: 0, fin: 0).
    //
    //           0  <-- start
    //          / \
    //         1   2
    //         |   |
    //         3   4
    //         |   |
    //         5   6
    //         |   |
    //         7   8
    //         |   |
    // head -> 9  10
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(0),
        justified_root: get_hash(0),
        finalized_epoch: Epoch::new(0),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(9),
    });
    // Save as above but justified epoch 2.
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(2),
        justified_root: get_hash(0),
        finalized_epoch: Epoch::new(0),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(9),
    });
    // Save as above but justified epoch 3 (should fail).
    ops.push(Operation::InvalidFindHead {
        justified_epoch: Epoch::new(3),
        justified_root: get_hash(0),
        finalized_epoch: Epoch::new(0),
        justified_state_balances: balances.clone(),
    });

    // Add a vote to 2.
    //
    //                 0
    //                / \
    //               1   2 <- +1 vote
    //               |   |
    //               3   4
    //               |   |
    //               5   6
    //               |   |
    //               7   8
    //               |   |
    //               9  10
    ops.push(Operation::ProcessAttestation {
        validator_index: 1,
        block_root: get_hash(2),
        target_epoch: Epoch::new(0),
    });

    // Ensure that if we start at 0 we find 10 (just: 0, fin: 0).
    //
    //           0  <-- start
    //          / \
    //         1   2
    //         |   |
    //         3   4
    //         |   |
    //         5   6
    //         |   |
    //         7   8
    //         |   |
    //         9  10 <-- head
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(0),
        justified_root: get_hash(0),
        finalized_epoch: Epoch::new(0),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(10),
    });
    // Same as above but justified epoch 2.
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(2),
        justified_root: get_hash(0),
        finalized_epoch: Epoch::new(0),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(10),
    });
    // Same as above but justified epoch 3 (should fail).
    ops.push(Operation::InvalidFindHead {
        justified_epoch: Epoch::new(3),
        justified_root: get_hash(0),
        finalized_epoch: Epoch::new(0),
        justified_state_balances: balances.clone(),
    });

    // Ensure that if we start at 1 we find 9 (just: 0, fin: 0).
    //
    //            0
    //           / \
    //  start-> 1   2
    //          |   |
    //          3   4
    //          |   |
    //          5   6
    //          |   |
    //          7   8
    //          |   |
    //  head -> 9  10
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(0),
        justified_root: get_hash(1),
        finalized_epoch: Epoch::new(0),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(9),
    });
    // Same as above but justified epoch 2.
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(2),
        justified_root: get_hash(1),
        finalized_epoch: Epoch::new(0),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(9),
    });
    // Same as above but justified epoch 3 (should fail).
    ops.push(Operation::InvalidFindHead {
        justified_epoch: Epoch::new(3),
        justified_root: get_hash(1),
        finalized_epoch: Epoch::new(0),
        justified_state_balances: balances.clone(),
    });

    // Ensure that if we start at 2 we find 10 (just: 0, fin: 0).
    //
    //            0
    //           / \
    //          1   2 <- start
    //          |   |
    //          3   4
    //          |   |
    //          5   6
    //          |   |
    //          7   8
    //          |   |
    //          9  10 <- head
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(0),
        justified_root: get_hash(2),
        finalized_epoch: Epoch::new(0),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(10),
    });
    // Same as above but justified epoch 2.
    ops.push(Operation::FindHead {
        justified_epoch: Epoch::new(2),
        justified_root: get_hash(2),
        finalized_epoch: Epoch::new(0),
        justified_state_balances: balances.clone(),
        expected_head: get_hash(10),
    });
    // Same as above but justified epoch 3 (should fail).
    ops.push(Operation::InvalidFindHead {
        justified_epoch: Epoch::new(3),
        justified_root: get_hash(2),
        finalized_epoch: Epoch::new(0),
        justified_state_balances: balances,
    });

    // END OF TESTS
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
    fn ffg_case_01() {
        let test = get_ffg_case_01_test_definition();
        test.run();
    }

    #[test]
    fn ffg_case_02() {
        let test = get_ffg_case_02_test_definition();
        test.run();
    }
}
