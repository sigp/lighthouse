use super::*;

fn gloas_spec() -> ChainSpec {
    let mut spec = MainnetEthSpec::default_spec();
    spec.proposer_score_boost = Some(50);
    spec.gloas_fork_epoch = Some(Epoch::new(0));
    spec
}

pub fn get_gloas_chain_following_test_definition() -> ForkChoiceTestDefinition {
    let mut ops = vec![];

    // Build two branches off genesis where one child extends parent's payload chain (Full)
    // and the other does not (Empty).
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(1),
        root: get_root(1),
        parent_root: get_root(0),
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        execution_payload_parent_hash: Some(get_hash(0)),
        execution_payload_block_hash: Some(get_hash(1)),
    });
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(1),
        root: get_root(2),
        parent_root: get_root(0),
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        execution_payload_parent_hash: Some(get_hash(99)),
        execution_payload_block_hash: Some(get_hash(2)),
    });

    // Extend both branches to verify that head selection follows the selected chain.
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(2),
        root: get_root(3),
        parent_root: get_root(1),
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        execution_payload_parent_hash: Some(get_hash(1)),
        execution_payload_block_hash: Some(get_hash(3)),
    });
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(2),
        root: get_root(4),
        parent_root: get_root(2),
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        execution_payload_parent_hash: Some(get_hash(100)),
        execution_payload_block_hash: Some(get_hash(4)),
    });

    ops.push(Operation::AssertParentPayloadStatus {
        block_root: get_root(1),
        expected_status: PayloadStatus::Full,
    });
    ops.push(Operation::AssertParentPayloadStatus {
        block_root: get_root(2),
        expected_status: PayloadStatus::Empty,
    });

    // With equal full/empty parent weights, tiebreak decides which chain to follow.
    ops.push(Operation::SetPayloadTiebreak {
        block_root: get_root(0),
        is_timely: true,
        is_data_available: true,
    });
    ops.push(Operation::FindHead {
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        justified_state_balances: vec![1],
        expected_head: get_root(3),
    });

    ops.push(Operation::SetPayloadTiebreak {
        block_root: get_root(0),
        is_timely: false,
        is_data_available: false,
    });
    ops.push(Operation::FindHead {
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        justified_state_balances: vec![1],
        expected_head: get_root(4),
    });

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

pub fn get_gloas_payload_probe_test_definition() -> ForkChoiceTestDefinition {
    let mut ops = vec![];

    ops.push(Operation::ProcessBlock {
        slot: Slot::new(1),
        root: get_root(1),
        parent_root: get_root(0),
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        execution_payload_parent_hash: Some(get_hash(0)),
        execution_payload_block_hash: Some(get_hash(1)),
    });

    // One Full and one Empty vote for the same head block: tie should probe as Full.
    ops.push(Operation::ProcessAttestation {
        validator_index: 0,
        block_root: get_root(1),
        attestation_slot: Slot::new(2),
        payload_present: true,
    });
    ops.push(Operation::ProcessAttestation {
        validator_index: 1,
        block_root: get_root(1),
        attestation_slot: Slot::new(2),
        payload_present: false,
    });
    ops.push(Operation::FindHead {
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        justified_state_balances: vec![1, 1],
        expected_head: get_root(1),
    });
    ops.push(Operation::AssertPayloadWeights {
        block_root: get_root(1),
        expected_full_weight: 1,
        expected_empty_weight: 1,
    });
    ops.push(Operation::AssertHeadPayloadStatus {
        head_root: get_root(1),
        expected_status: PayloadStatus::Full,
    });

    // Flip validator 0 to Empty; probe should now report Empty.
    ops.push(Operation::ProcessAttestation {
        validator_index: 0,
        block_root: get_root(1),
        attestation_slot: Slot::new(3),
        payload_present: false,
    });
    ops.push(Operation::FindHead {
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        justified_state_balances: vec![1, 1],
        expected_head: get_root(1),
    });
    ops.push(Operation::AssertPayloadWeights {
        block_root: get_root(1),
        expected_full_weight: 0,
        expected_empty_weight: 2,
    });
    ops.push(Operation::AssertHeadPayloadStatus {
        head_root: get_root(1),
        expected_status: PayloadStatus::Empty,
    });

    // Same-slot attestation to a new head candidate should be Pending (no payload bucket change).
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(3),
        root: get_root(5),
        parent_root: get_root(1),
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        execution_payload_parent_hash: Some(get_hash(1)),
        execution_payload_block_hash: Some(get_hash(5)),
    });
    ops.push(Operation::ProcessAttestation {
        validator_index: 2,
        block_root: get_root(5),
        attestation_slot: Slot::new(3),
        payload_present: true,
    });
    ops.push(Operation::FindHead {
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        justified_state_balances: vec![1, 1, 1],
        expected_head: get_root(5),
    });
    ops.push(Operation::AssertPayloadWeights {
        block_root: get_root(5),
        expected_full_weight: 0,
        expected_empty_weight: 0,
    });
    ops.push(Operation::AssertHeadPayloadStatus {
        head_root: get_root(5),
        expected_status: PayloadStatus::Full,
    });

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

    #[test]
    fn chain_following() {
        let test = get_gloas_chain_following_test_definition();
        test.run();
    }

    #[test]
    fn payload_probe() {
        let test = get_gloas_payload_probe_test_definition();
        test.run();
    }
}
