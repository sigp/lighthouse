use super::*;

fn gloas_spec() -> ChainSpec {
    let mut spec = MainnetEthSpec::default_spec();
    spec.proposer_score_boost = 50;
    spec.gloas_fork_epoch = Some(Epoch::new(0));
    spec
}

fn gloas_definition(operations: Vec<Operation>) -> ForkChoiceTestDefinition {
    ForkChoiceTestDefinition {
        finalized_block_slot: Slot::new(0),
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        operations,
        execution_payload_parent_hash: Some(get_hash(42)),
        execution_payload_block_hash: Some(get_hash(0)),
        spec: Some(gloas_spec()),
    }
}

/// Assert the regular, `FULL` and `EMPTY` weights of `block_root`.
fn assert_weights(block_root: Hash256, weight: u64, full: u64, empty: u64) -> Vec<Operation> {
    vec![
        Operation::AssertWeight { block_root, weight },
        Operation::AssertPayloadWeights {
            block_root,
            expected_full_weight: full,
            expected_empty_weight: empty,
        },
    ]
}

/// Invalidate the payload of a Gloas block with weight on both payload sides, then move votes
/// around and reset every verdict.
///
/// ```text
///          0
///          | EMPTY
///          1  <- payload invalidated
///   FULL  / \  EMPTY
///        2   3
/// ```
///
/// Validator balances are powers of two, so each weight shows which votes it holds.
pub fn get_gloas_invalid_payload_weights_test_definition() -> ForkChoiceTestDefinition {
    let balances = vec![1, 2, 4, 8];
    let mut ops = vec![
        Operation::ProcessBlock {
            slot: Slot::new(1),
            root: get_root(1),
            parent_root: get_root(0),
            justified_checkpoint: get_checkpoint(0),
            finalized_checkpoint: get_checkpoint(0),
            execution_payload_parent_hash: Some(get_hash(42)),
            execution_payload_block_hash: Some(get_hash(1)),
        },
        Operation::ProcessBlock {
            slot: Slot::new(2),
            root: get_root(2),
            parent_root: get_root(1),
            justified_checkpoint: get_checkpoint(0),
            finalized_checkpoint: get_checkpoint(0),
            execution_payload_parent_hash: Some(get_hash(1)),
            execution_payload_block_hash: Some(get_hash(2)),
        },
        Operation::ProcessBlock {
            slot: Slot::new(2),
            root: get_root(3),
            parent_root: get_root(1),
            justified_checkpoint: get_checkpoint(0),
            finalized_checkpoint: get_checkpoint(0),
            execution_payload_parent_hash: Some(get_hash(42)),
            execution_payload_block_hash: Some(get_hash(3)),
        },
        Operation::AssertParentPayloadStatus {
            block_root: get_root(2),
            expected_status: ParentPayloadStatus::Full,
        },
        Operation::AssertParentPayloadStatus {
            block_root: get_root(3),
            expected_status: ParentPayloadStatus::Empty,
        },
        // Only block 1 has its envelope; block 2 commits to a payload that never arrives.
        Operation::ProcessOptimisticExecutionPayloadEnvelope {
            block_root: get_root(1),
            block_hash: get_hash(1),
        },
        // Validator 0 votes `FULL` on 1 and validator 1 votes `EMPTY` on 1. Validator 2 votes for
        // the `FULL` child 2 and validator 3 for the `EMPTY` child 3.
        Operation::ProcessGloasAttestation {
            validator_index: 0,
            block_root: get_root(1),
            attestation_slot: Slot::new(5),
            payload_present: true,
        },
        Operation::ProcessGloasAttestation {
            validator_index: 1,
            block_root: get_root(1),
            attestation_slot: Slot::new(5),
            payload_present: false,
        },
        Operation::ProcessGloasAttestation {
            validator_index: 2,
            block_root: get_root(2),
            attestation_slot: Slot::new(5),
            payload_present: true,
        },
        Operation::ProcessGloasAttestation {
            validator_index: 3,
            block_root: get_root(3),
            attestation_slot: Slot::new(5),
            payload_present: false,
        },
        Operation::ApplyScoreChanges {
            justified_state_balances: balances.clone(),
            current_slot: Slot::new(5),
        },
    ];
    ops.extend(assert_weights(get_root(0), 15, 0, 15));
    ops.extend(assert_weights(get_root(1), 15, 5, 10));
    ops.extend(assert_weights(get_root(2), 4, 4, 0));
    ops.extend(assert_weights(get_root(3), 8, 0, 8));

    // Invalidate the payload of block 1. The sweep condemns its `FULL` child 2 too, even though
    // the payload of 2 never arrived.
    ops.push(Operation::InvalidatePayload {
        head_hash: get_hash(1),
        latest_valid_ancestor: None,
    });
    ops.push(Operation::AssertExecutionStatus {
        block_root: get_root(1),
        expected: ExecutionStatus::Invalid(get_hash(1)),
    });
    ops.push(Operation::AssertExecutionStatus {
        block_root: get_root(2),
        expected: ExecutionStatus::Invalid(get_hash(2)),
    });
    ops.push(Operation::AssertExecutionStatus {
        block_root: get_root(3),
        expected: ExecutionStatus::NotYetRevealed(get_hash(3)),
    });
    ops.push(Operation::ApplyScoreChanges {
        justified_state_balances: balances.clone(),
        current_slot: Slot::new(5),
    });
    // The invalid node drops its `FULL` weight and keeps its `EMPTY` weight.
    ops.extend(assert_weights(get_root(1), 10, 0, 10));
    // The `FULL` child is invalid as a whole.
    ops.extend(assert_weights(get_root(2), 0, 0, 0));
    // The `EMPTY` child keeps its weight and still passes it up through 1.
    ops.extend(assert_weights(get_root(3), 8, 0, 8));
    // Neither validator 0 nor the `FULL` child 2 reach past the invalid node.
    ops.extend(assert_weights(get_root(0), 10, 0, 10));

    // Validator 0 moves its `FULL` vote on 1 to 3. Its weight already left 1 on invalidation, so
    // 1 and 0 only gain the vote through 3 and lose nothing.
    ops.push(Operation::ProcessGloasAttestation {
        validator_index: 0,
        block_root: get_root(3),
        attestation_slot: Slot::new(6),
        payload_present: false,
    });
    ops.push(Operation::ApplyScoreChanges {
        justified_state_balances: balances.clone(),
        current_slot: Slot::new(6),
    });
    ops.extend(assert_weights(get_root(3), 9, 0, 9));
    ops.extend(assert_weights(get_root(1), 11, 0, 11));
    ops.extend(assert_weights(get_root(0), 11, 0, 11));

    // Validator 1 moves its `EMPTY` vote on 1 to `FULL` on 1. The new vote targets the invalid
    // `FULL` side, so 1 and 0 lose the old vote and gain nothing.
    ops.push(Operation::ProcessGloasAttestation {
        validator_index: 1,
        block_root: get_root(1),
        attestation_slot: Slot::new(7),
        payload_present: true,
    });
    ops.push(Operation::ApplyScoreChanges {
        justified_state_balances: balances.clone(),
        current_slot: Slot::new(7),
    });
    ops.extend(assert_weights(get_root(1), 9, 0, 9));
    ops.extend(assert_weights(get_root(0), 9, 0, 9));

    // A restart forgets every verdict and rebuilds the weights from the current votes, as if the
    // invalidation never happened.
    ops.push(Operation::SetAllBlocksToOptimistic);
    // Block 1 has its envelope, so it goes back to `Optimistic`.
    ops.push(Operation::AssertExecutionStatus {
        block_root: get_root(1),
        expected: ExecutionStatus::Optimistic(get_hash(1)),
    });
    ops.push(Operation::AssertExecutionStatus {
        block_root: get_root(3),
        expected: ExecutionStatus::NotYetRevealed(get_hash(3)),
    });
    ops.extend(assert_weights(get_root(3), 9, 0, 9));
    ops.extend(assert_weights(get_root(2), 4, 4, 0));
    ops.extend(assert_weights(get_root(1), 15, 6, 9));
    ops.extend(assert_weights(get_root(0), 15, 0, 15));

    gloas_definition(ops)
}

/// A failed envelope import leaves `payload_received` false and changes no execution status. The
/// caller also skips the database write.
///
/// ```text
///   0
///   | EMPTY
///   1  <- payload invalid
///   | FULL
///   2  <- envelope received as VALID
/// ```
pub fn get_gloas_failed_envelope_not_received_test_definition() -> ForkChoiceTestDefinition {
    gloas_definition(vec![
        Operation::ProcessBlock {
            slot: Slot::new(1),
            root: get_root(1),
            parent_root: get_root(0),
            justified_checkpoint: get_checkpoint(0),
            finalized_checkpoint: get_checkpoint(0),
            execution_payload_parent_hash: Some(get_hash(42)),
            execution_payload_block_hash: Some(get_hash(1)),
        },
        Operation::ProcessBlock {
            slot: Slot::new(2),
            root: get_root(2),
            parent_root: get_root(1),
            justified_checkpoint: get_checkpoint(0),
            finalized_checkpoint: get_checkpoint(0),
            execution_payload_parent_hash: Some(get_hash(1)),
            execution_payload_block_hash: Some(get_hash(2)),
        },
        // The sweep also marks 2 invalid, so mark only 1.
        Operation::SetExecutionStatus {
            block_root: get_root(1),
            execution_status: ExecutionStatus::Invalid(get_hash(1)),
        },
        Operation::InvalidProcessExecutionPayloadEnvelope {
            block_root: get_root(2),
        },
        Operation::AssertPayloadReceived {
            block_root: get_root(2),
            expected: false,
        },
        Operation::AssertExecutionStatus {
            block_root: get_root(2),
            expected: ExecutionStatus::NotYetRevealed(get_hash(2)),
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_payload_weights() {
        get_gloas_invalid_payload_weights_test_definition().run();
    }

    #[test]
    fn failed_envelope_not_received() {
        get_gloas_failed_envelope_not_received_test_definition().run();
    }
}
