use super::*;
use crate::fork_choice_test_definition::gloas_payload::gloas_spec;

/// Chain: A(0) <- N-1(1, EMPTY edge, payload VALID) <- N(2, FULL edge) <- N+1(3). Payload N is
/// one of: VALID from an EL, never in fork choice, OPTIMISTIC (eagerly imported, proof not yet
/// in), PROVEN (OPTIMISTIC then VALID). The node attests once in slot N before payload N, once
/// after it, and once in slot N+1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadN {
    Valid,
    NotImported,
    Optimistic,
    Proven,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotN1 {
    Full,
    Empty,
    Missed,
    /// N+1 on FULL, a sibling N+1' on EMPTY.
    FullWithEmptySibling,
}

const BALANCES: [u64; 1] = [32];

fn block(slot: u64, root: u64, parent: u64, parent_hash: u64) -> Operation {
    Operation::ProcessBlock {
        slot: Slot::new(slot),
        root: get_root(root),
        parent_root: get_root(parent),
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        execution_payload_parent_hash: Some(get_hash(parent_hash)),
        execution_payload_block_hash: Some(get_hash(root)),
    }
}

fn find_head(current_slot: u64, root: u64, payload_status: PayloadStatus) -> Operation {
    Operation::FindHead {
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        justified_state_balances: BALANCES.to_vec(),
        expected_head: get_root(root),
        current_slot: Slot::new(current_slot),
        expected_payload_status: Some(payload_status),
    }
}

fn verdict(root: u64, payload_status: PayloadStatus, expected: ExecutionVerdict) -> Operation {
    Operation::AssertExecutionVerdict {
        block_root: get_root(root),
        payload_status,
        expected,
    }
}

/// With `filter_optimistic_payloads`, an eagerly imported optimistic payload gives the same head
/// as a payload that is not in fork choice yet. Only a verified payload has a FULL node.
pub fn get_filter_optimistic_payloads_test_definition(
    payload_n: PayloadN,
    slot_n1: SlotN1,
) -> ForkChoiceTestDefinition {
    let full = match payload_n {
        PayloadN::Valid | PayloadN::Proven => true,
        PayloadN::NotImported | PayloadN::Optimistic => false,
    };
    let mut ops = vec![
        Operation::SetFilterOptimisticPayloads { enabled: true },
        block(1, 1, 0, 99),
        Operation::ProcessExecutionPayloadEnvelope {
            block_root: get_root(1),
        },
        block(2, 2, 1, 1),
        find_head(2, 2, PayloadStatus::Empty),
    ];
    match payload_n {
        PayloadN::Valid => ops.push(Operation::ProcessExecutionPayloadEnvelope {
            block_root: get_root(2),
        }),
        PayloadN::NotImported => {}
        PayloadN::Optimistic => ops.push(Operation::ProcessOptimisticExecutionPayloadEnvelope {
            block_root: get_root(2),
        }),
        PayloadN::Proven => {
            ops.push(Operation::ProcessOptimisticExecutionPayloadEnvelope {
                block_root: get_root(2),
            });
            ops.push(Operation::ProcessExecutionPayloadEnvelope {
                block_root: get_root(2),
            });
        }
    }
    let n_status = if full {
        PayloadStatus::Full
    } else {
        PayloadStatus::Empty
    };
    ops.push(find_head(2, 2, n_status));
    ops.push(verdict(2, n_status, ExecutionVerdict::Valid));
    let (head, status) = match slot_n1 {
        SlotN1::Full => {
            ops.push(block(3, 3, 2, 2));
            if full {
                (3, PayloadStatus::Empty)
            } else {
                (2, PayloadStatus::Empty)
            }
        }
        SlotN1::Empty => {
            ops.push(block(3, 3, 2, 1));
            if full {
                (2, PayloadStatus::Full)
            } else {
                (3, PayloadStatus::Empty)
            }
        }
        SlotN1::Missed => (2, n_status),
        SlotN1::FullWithEmptySibling => {
            ops.push(block(3, 3, 2, 2));
            ops.push(block(3, 4, 2, 1));
            if full {
                (3, PayloadStatus::Empty)
            } else {
                (4, PayloadStatus::Empty)
            }
        }
    };
    ops.push(find_head(3, head, status));
    ops.push(verdict(head, status, ExecutionVerdict::Valid));

    ForkChoiceTestDefinition {
        finalized_block_slot: Slot::new(0),
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        operations: ops,
        execution_payload_parent_hash: Some(get_hash(42)),
        execution_payload_block_hash: Some(get_hash(0)),
        spec: Some(gloas_spec()),
    }
}

/// Without the switch an optimistic payload has a FULL node, and the head rests on it.
pub fn get_optimistic_payload_without_filter_test_definition() -> ForkChoiceTestDefinition {
    let ops = vec![
        block(1, 1, 0, 99),
        Operation::ProcessExecutionPayloadEnvelope {
            block_root: get_root(1),
        },
        block(2, 2, 1, 1),
        Operation::ProcessOptimisticExecutionPayloadEnvelope {
            block_root: get_root(2),
        },
        find_head(2, 2, PayloadStatus::Full),
        verdict(2, PayloadStatus::Full, ExecutionVerdict::Optimistic),
        block(3, 3, 2, 2),
        find_head(3, 3, PayloadStatus::Empty),
        verdict(3, PayloadStatus::Empty, ExecutionVerdict::Optimistic),
    ];
    ForkChoiceTestDefinition {
        finalized_block_slot: Slot::new(0),
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        operations: ops,
        execution_payload_parent_hash: Some(get_hash(42)),
        execution_payload_block_hash: Some(get_hash(0)),
        spec: Some(gloas_spec()),
    }
}

/// A(0) <- B(1, EMPTY edge, OPTIMISTIC) <- J(2, FULL edge, OPTIMISTIC) <- N(3, FULL edge), with
/// J justified. Nothing above J has a FULL node, so J is the head on EMPTY, and that node is
/// optimistic because it rests on B's payload.
pub fn get_optimistic_justified_node_test_definition() -> ForkChoiceTestDefinition {
    let justified = Checkpoint {
        epoch: Epoch::new(0),
        root: get_root(2),
    };
    let ops = vec![
        Operation::SetFilterOptimisticPayloads { enabled: true },
        block(1, 1, 0, 99),
        Operation::ProcessOptimisticExecutionPayloadEnvelope {
            block_root: get_root(1),
        },
        block(2, 2, 1, 1),
        Operation::ProcessOptimisticExecutionPayloadEnvelope {
            block_root: get_root(2),
        },
        block(3, 3, 2, 2),
        Operation::FindHead {
            justified_checkpoint: justified,
            finalized_checkpoint: get_checkpoint(0),
            justified_state_balances: BALANCES.to_vec(),
            expected_head: get_root(2),
            current_slot: Slot::new(3),
            expected_payload_status: Some(PayloadStatus::Empty),
        },
        verdict(2, PayloadStatus::Empty, ExecutionVerdict::Optimistic),
    ];
    ForkChoiceTestDefinition {
        finalized_block_slot: Slot::new(0),
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        operations: ops,
        execution_payload_parent_hash: Some(get_hash(42)),
        execution_payload_block_hash: Some(get_hash(0)),
        spec: Some(gloas_spec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SLOT_N1: [SlotN1; 4] = [
        SlotN1::Full,
        SlotN1::Empty,
        SlotN1::Missed,
        SlotN1::FullWithEmptySibling,
    ];

    #[test]
    fn late_proof_matches_a_payload_not_imported() {
        for slot_n1 in SLOT_N1 {
            get_filter_optimistic_payloads_test_definition(PayloadN::Optimistic, slot_n1).run();
            get_filter_optimistic_payloads_test_definition(PayloadN::NotImported, slot_n1).run();
        }
    }

    #[test]
    fn verified_payloads_keep_the_full_node() {
        for slot_n1 in SLOT_N1 {
            get_filter_optimistic_payloads_test_definition(PayloadN::Valid, slot_n1).run();
            get_filter_optimistic_payloads_test_definition(PayloadN::Proven, slot_n1).run();
        }
    }

    #[test]
    fn optimistic_payload_without_filter() {
        get_optimistic_payload_without_filter_test_definition().run();
    }

    #[test]
    fn optimistic_justified_node_is_head() {
        get_optimistic_justified_node_test_definition().run();
    }
}
