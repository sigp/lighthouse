use super::*;

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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test() {
        let test = get_no_votes_test_definition();
        test.run();
    }
}
