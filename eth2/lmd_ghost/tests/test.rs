use lmd_ghost::ProtoArrayForkChoice;
use types::{Epoch, Hash256};

/// Gives a hash that is not the zero hash (unless i is `usize::max_value)`.
fn get_hash(i: u64) -> Hash256 {
    Hash256::from_low_u64_be(i)
}

/// This tests does not use any validator votes, it just relies on hash-sorting to find the
/// head.
#[test]
fn no_votes() {
    const VALIDATOR_COUNT: usize = 16;

    let fork_choice = ProtoArrayForkChoice::new(Epoch::new(0), Epoch::new(0), get_hash(0))
        .expect("should create fork choice");

    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(0),
                Hash256::zero(),
                Epoch::new(0),
                Hash256::zero(),
                &[0; VALIDATOR_COUNT]
            )
            .expect("should find head"),
        Hash256::zero(),
        "should find genesis block as root when there is only one block"
    );

    // Add block 2
    //
    //         0
    //        /
    //        2
    fork_choice
        .process_block(get_hash(2), get_hash(0), Epoch::new(0), Epoch::new(0))
        .expect("should process block");

    // Ensure the head is 2
    //
    //         0
    //        /
    //        2 <- head
    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(0),
                Hash256::zero(),
                Epoch::new(0),
                Hash256::zero(),
                &[0; VALIDATOR_COUNT]
            )
            .expect("should find head"),
        get_hash(2),
        "should find head block with a single chain"
    );

    // Add block 1
    //
    //         0
    //        / \
    //        2  1
    fork_choice
        .process_block(get_hash(1), get_hash(0), Epoch::new(0), Epoch::new(0))
        .expect("should process block");

    // Ensure the head is still 2
    //
    //         0
    //        / \
    // head-> 2  1
    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(0),
                Hash256::zero(),
                Epoch::new(0),
                Hash256::zero(),
                &[0; VALIDATOR_COUNT]
            )
            .expect("should find head"),
        get_hash(2),
        "should find the first block, not the second block (it should compare hashes)"
    );

    // Add block 3
    //
    //         0
    //        / \
    //        2  1
    //           |
    //           3
    fork_choice
        .process_block(get_hash(3), get_hash(1), Epoch::new(0), Epoch::new(0))
        .expect("should process block");

    // Ensure 3 is the head
    //
    //         0
    //        / \
    //        2  1
    //           |
    //           3 <- head
    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(0),
                Hash256::zero(),
                Epoch::new(0),
                Hash256::zero(),
                &[0; VALIDATOR_COUNT]
            )
            .expect("should find head"),
        get_hash(2),
        "should find the get_hash(2) block"
    );

    // Add block 4
    //
    //         0
    //        / \
    //        2  1
    //        |  |
    //        4  3
    fork_choice
        .process_block(get_hash(4), get_hash(2), Epoch::new(0), Epoch::new(0))
        .expect("should process block");

    // Ensure the head is 4.
    //
    //         0
    //        / \
    //        2  1
    //        |  |
    // head-> 4  3
    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(0),
                Hash256::zero(),
                Epoch::new(0),
                Hash256::zero(),
                &[0; VALIDATOR_COUNT]
            )
            .expect("should find head"),
        get_hash(4),
        "should find the get_hash(4) block"
    );

    // Ensure the head is still 4 whilst the justified epoch is 0.
    //
    //         0
    //        / \
    //        2  1
    //        |  |
    //        4  3
    //        |
    //        5 <- justified epoch = 1
    fork_choice
        .process_block(get_hash(5), get_hash(4), Epoch::new(1), Epoch::new(0))
        .expect("should process block");

    // Ensure the head is still 4 whilst the justified epoch is 0.
    //
    //         0
    //        / \
    //        2  1
    //        |  |
    // head-> 4  3
    //        |
    //        5
    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(0),
                Hash256::zero(),
                Epoch::new(0),
                Hash256::zero(),
                &[0; VALIDATOR_COUNT]
            )
            .expect("should find head"),
        get_hash(4),
        "should find the get_hash(4) block because the get_hash(5) should be filtered out"
    );

    // Ensure there is an error when starting from a block that has the wrong justified epoch.
    //
    //      0
    //     / \
    //     2  1
    //     |  |
    //     4  3
    //     |
    //     5 <- starting from 5 with justified epoch 0 should error.
    assert!(
        fork_choice
            .find_head(
                Epoch::new(0),
                get_hash(5),
                Epoch::new(0),
                Hash256::zero(),
                &[0; VALIDATOR_COUNT]
            )
            .is_err(),
        "should not allow finding head from a bad justified epoch"
    );

    // Set the justified epoch to 1 and the start block to 5 and ensure 5 is the head.
    //
    //      0
    //     / \
    //     2  1
    //     |  |
    //     4  3
    //     |
    //     5 <- head
    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(1),
                get_hash(5),
                Epoch::new(0),
                Hash256::zero(),
                &[0; VALIDATOR_COUNT]
            )
            .expect("should find head"),
        get_hash(5),
        "should find the get_hash(5) block"
    );

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
    fork_choice
        .process_block(get_hash(6), get_hash(5), Epoch::new(1), Epoch::new(0))
        .expect("should process block");

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
    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(1),
                get_hash(5),
                Epoch::new(0),
                Hash256::zero(),
                &[0; VALIDATOR_COUNT]
            )
            .expect("should find head"),
        get_hash(6),
        "should find the get_hash(6) block"
    );
}

/// This test uses validator votes and tests weight assignment.
#[test]
fn votes() {
    const VALIDATOR_COUNT: usize = 2;
    let balances = vec![1; VALIDATOR_COUNT];

    let fork_choice = ProtoArrayForkChoice::new(Epoch::new(0), Epoch::new(0), get_hash(0))
        .expect("should create fork choice");

    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(0),
                Hash256::zero(),
                Epoch::new(0),
                Hash256::zero(),
                &balances
            )
            .expect("should find head"),
        Hash256::zero(),
        "should find genesis block as root when there is only one block"
    );

    // Add a block with a hash of 2.
    //
    //          0
    //         /
    //        2
    fork_choice
        .process_block(get_hash(2), get_hash(0), Epoch::new(0), Epoch::new(0))
        .expect("should process block");

    // Ensure that the head is 2
    //
    //          0
    //         /
    // head-> 2
    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(0),
                Hash256::zero(),
                Epoch::new(0),
                Hash256::zero(),
                &balances
            )
            .expect("should find head"),
        get_hash(2),
        "should find head block with a single chain"
    );

    // Add a block with a hash of 1 that comes off the genesis block (this is a fork compared
    // to the previous block).
    //
    //          0
    //         / \
    //        2   1
    fork_choice
        .process_block(get_hash(1), get_hash(0), Epoch::new(0), Epoch::new(0))
        .expect("should process block");

    // Ensure that the head is 2
    //
    //          0
    //         / \
    // head-> 2   1
    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(0),
                Hash256::zero(),
                Epoch::new(0),
                Hash256::zero(),
                &balances
            )
            .expect("should find head"),
        get_hash(2),
        "should find get_hash(2), not get_hash(1) (it should compare hashes)"
    );

    // Add a vote to block 1
    //
    //          0
    //         / \
    //        2   1 <- +vote
    fork_choice
        .process_attestation(0, get_hash(1), Epoch::new(1))
        .expect("should process attestation");

    // Ensure that the head is now 1, beacuse 1 has a vote.
    //
    //          0
    //         / \
    //        2   1 <- head
    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(0),
                Hash256::zero(),
                Epoch::new(0),
                Hash256::zero(),
                &balances
            )
            .expect("should find head"),
        get_hash(1),
        "should find the get_hash(1) because it now has a vote"
    );

    // Add a vote to block 2
    //
    //           0
    //          / \
    // +vote-> 2   1
    fork_choice
        .process_attestation(1, get_hash(2), Epoch::new(1))
        .expect("should process attestation");

    // Ensure that the head is 2 since 1 and 2 both have a vote
    //
    //          0
    //         / \
    // head-> 2   1
    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(0),
                Hash256::zero(),
                Epoch::new(0),
                Hash256::zero(),
                &balances
            )
            .expect("should find head"),
        get_hash(2),
        "should find get_hash(2)"
    );

    // Add block 3.
    //
    //          0
    //         / \
    //        2   1
    //            |
    //            3
    fork_choice
        .process_block(get_hash(3), get_hash(1), Epoch::new(0), Epoch::new(0))
        .expect("should process block");

    // Ensure that the head is still 2
    //
    //          0
    //         / \
    // head-> 2   1
    //            |
    //            3
    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(0),
                Hash256::zero(),
                Epoch::new(0),
                Hash256::zero(),
                &balances
            )
            .expect("should find head"),
        get_hash(2),
        "should find get_hash(2)"
    );

    // Move validator #0 vote from 1 to 3
    //
    //          0
    //         / \
    //        2   1 <- -vote
    //            |
    //            3 <- +vote
    fork_choice
        .process_attestation(0, get_hash(3), Epoch::new(2))
        .expect("should process attestation");

    // Ensure that the head is still 2
    //
    //          0
    //         / \
    // head-> 2   1
    //            |
    //            3
    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(0),
                Hash256::zero(),
                Epoch::new(0),
                Hash256::zero(),
                &balances
            )
            .expect("should find head"),
        get_hash(2),
        "should find get_hash(2)"
    );

    // Move validator #1 vote from 2 to 1 (this is an equivocation, but fork choice doesn't
    // care)
    //
    //           0
    //          / \
    // -vote-> 2   1 <- +vote
    //             |
    //             3
    fork_choice
        .process_attestation(1, get_hash(1), Epoch::new(2))
        .expect("should process attestation");

    // Ensure that the head is now 3
    //
    //          0
    //         / \
    //        2   1
    //            |
    //            3 <- head
    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(0),
                Hash256::zero(),
                Epoch::new(0),
                Hash256::zero(),
                &balances
            )
            .expect("should find head"),
        get_hash(3),
        "should find get_hash(3)"
    );

    // Add block 4.
    //
    //          0
    //         / \
    //        2   1
    //            |
    //            3
    //            |
    //            4
    fork_choice
        .process_block(get_hash(4), get_hash(3), Epoch::new(0), Epoch::new(0))
        .expect("should process block");

    // Ensure that the head is now 4
    //
    //          0
    //         / \
    //        2   1
    //            |
    //            3
    //            |
    //            4 <- head
    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(0),
                Hash256::zero(),
                Epoch::new(0),
                Hash256::zero(),
                &balances
            )
            .expect("should find head"),
        get_hash(4),
        "should find get_hash(4)"
    );

    // Add block 5, which has a justified epoch of 1.
    //
    //          0
    //         / \
    //        2   1
    //            |
    //            3
    //            |
    //            4
    //           /
    //          5 <- justified epoch = 1
    fork_choice
        .process_block(get_hash(5), get_hash(4), Epoch::new(1), Epoch::new(1))
        .expect("should process block");

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
    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(0),
                Hash256::zero(),
                Epoch::new(0),
                Hash256::zero(),
                &balances
            )
            .expect("should find head"),
        get_hash(4),
        "should find get_hash(4)"
    );

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
    fork_choice
        .process_block(get_hash(6), get_hash(4), Epoch::new(0), Epoch::new(0))
        .expect("should process block");

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
    fork_choice
        .process_attestation(0, get_hash(5), Epoch::new(3))
        .expect("should process attestation");
    fork_choice
        .process_attestation(1, get_hash(5), Epoch::new(3))
        .expect("should process attestation");

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
    fork_choice
        .process_block(get_hash(7), get_hash(5), Epoch::new(1), Epoch::new(1))
        .expect("should process block");
    fork_choice
        .process_block(get_hash(8), get_hash(7), Epoch::new(1), Epoch::new(1))
        .expect("should process block");
    fork_choice
        .process_block(get_hash(9), get_hash(8), Epoch::new(1), Epoch::new(1))
        .expect("should process block");

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
    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(0),
                Hash256::zero(),
                Epoch::new(0),
                Hash256::zero(),
                &balances
            )
            .expect("should find head"),
        get_hash(6),
        "should find get_hash(6)"
    );

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
    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(1),
                get_hash(5),
                Epoch::new(1),
                get_hash(5),
                &balances
            )
            .expect("should find head"),
        get_hash(9),
        "should find get_hash(9)"
    );

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
    fork_choice
        .process_attestation(0, get_hash(9), Epoch::new(4))
        .expect("should process attestation");
    fork_choice
        .process_attestation(1, get_hash(9), Epoch::new(4))
        .expect("should process attestation");

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
    fork_choice
        .process_block(get_hash(10), get_hash(8), Epoch::new(1), Epoch::new(1))
        .expect("should process block");

    // Double-check the head is still 9 (no diagram this time)
    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(1),
                get_hash(5),
                Epoch::new(1),
                get_hash(5),
                &balances
            )
            .expect("should find head"),
        get_hash(9),
        "should find get_hash(9)"
    );

    // Introduce 2 more validators into the system
    let balances = vec![1; 4];

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
    fork_choice
        .process_attestation(2, get_hash(10), Epoch::new(4))
        .expect("should process attestation");
    fork_choice
        .process_attestation(3, get_hash(10), Epoch::new(4))
        .expect("should process attestation");

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
    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(1),
                get_hash(5),
                Epoch::new(1),
                get_hash(5),
                &balances
            )
            .expect("should find head"),
        get_hash(10),
        "should find get_hash(10)"
    );

    // Set the balances of the last two validators to zero
    let balances = vec![1, 1, 0, 0];

    // Check the head is 9 again.
    //
    //          .
    //          .
    //          .
    //          |
    //          8
    //         / \
    // head-> 9  10
    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(1),
                get_hash(5),
                Epoch::new(1),
                get_hash(5),
                &balances
            )
            .expect("should find head"),
        get_hash(9),
        "should find get_hash(9)"
    );

    // Set the balances of the last two validators back to 1
    let balances = vec![1; 4];

    // Check the head is 10.
    //
    //          .
    //          .
    //          .
    //          |
    //          8
    //         / \
    //        9  10 <- head
    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(1),
                get_hash(5),
                Epoch::new(1),
                get_hash(5),
                &balances
            )
            .expect("should find head"),
        get_hash(10),
        "should find get_hash(10)"
    );

    // Remove the last two validators
    let balances = vec![1; 2];

    // Check the head is 9 again.
    //
    //  (prior blocks ommitted)
    //          .
    //          .
    //          .
    //          |
    //          8
    //         / \
    // head-> 9  10
    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(1),
                get_hash(5),
                Epoch::new(1),
                get_hash(5),
                &balances
            )
            .expect("should find head"),
        get_hash(9),
        "should find get_hash(9)"
    );

    // Set pruning to an unreachable value.
    fork_choice.set_prune_threshold(usize::max_value());

    // Run find-head to trigger a prune.
    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(1),
                get_hash(5),
                Epoch::new(1),
                get_hash(5),
                &balances
            )
            .expect("should find head"),
        get_hash(9),
        "should find get_hash(9)"
    );

    // Ensure that no pruning happened.
    assert_eq!(fork_choice.len(), 11, "there should be 11 blocks");

    // Set pruning to a value that will result in a prune.
    fork_choice.set_prune_threshold(1);

    // Run find-head to trigger a prune.
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
    // head-> 9  10
    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(1),
                get_hash(5),
                Epoch::new(1),
                get_hash(5),
                &balances
            )
            .expect("should find head"),
        get_hash(9),
        "should find get_hash(9)"
    );

    // Ensure that pruning happened.
    assert_eq!(fork_choice.len(), 6, "there should be 6 blocks");

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
    fork_choice
        .process_block(get_hash(11), get_hash(9), Epoch::new(1), Epoch::new(1))
        .expect("should process block");

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
    assert_eq!(
        fork_choice
            .find_head(
                Epoch::new(1),
                get_hash(5),
                Epoch::new(1),
                get_hash(5),
                &balances
            )
            .expect("should find head"),
        get_hash(11),
        "should find get_hash(11)"
    );
}
