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

    // One Full and one Empty vote for the same head block: tie probes via runtime tiebreak,
    // which defaults to Empty unless timely+data-available evidence is set.
    ops.push(Operation::ProcessPayloadAttestation {
        validator_index: 0,
        block_root: get_root(1),
        attestation_slot: Slot::new(2),
        payload_present: true,
        blob_data_available: false,
    });
    ops.push(Operation::ProcessPayloadAttestation {
        validator_index: 1,
        block_root: get_root(1),
        attestation_slot: Slot::new(2),
        payload_present: false,
        blob_data_available: false,
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
        expected_status: PayloadStatus::Empty,
    });

    // Flip validator 0 to Empty; probe should now report Empty.
    ops.push(Operation::ProcessPayloadAttestation {
        validator_index: 0,
        block_root: get_root(1),
        attestation_slot: Slot::new(3),
        payload_present: false,
        blob_data_available: false,
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
    ops.push(Operation::ProcessPayloadAttestation {
        validator_index: 2,
        block_root: get_root(5),
        attestation_slot: Slot::new(3),
        payload_present: true,
        blob_data_available: false,
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
        expected_status: PayloadStatus::Empty,
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

pub fn get_gloas_find_head_vote_transition_test_definition() -> ForkChoiceTestDefinition {
    let mut ops = vec![];

    // Competing branches with distinct payload ancestry (Full vs Empty from genesis).
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

    // Equal branch weights: tiebreak FULL picks branch rooted at 3.
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

    // Validator 0 votes Empty branch -> head flips to 4.
    ops.push(Operation::ProcessPayloadAttestation {
        validator_index: 0,
        block_root: get_root(4),
        attestation_slot: Slot::new(3),
        payload_present: false,
        blob_data_available: false,
    });
    ops.push(Operation::FindHead {
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        justified_state_balances: vec![1],
        expected_head: get_root(4),
    });

    // Latest-message update back to Full branch -> head returns to 3.
    ops.push(Operation::ProcessPayloadAttestation {
        validator_index: 0,
        block_root: get_root(3),
        attestation_slot: Slot::new(4),
        payload_present: true,
        blob_data_available: false,
    });
    ops.push(Operation::FindHead {
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        justified_state_balances: vec![1],
        expected_head: get_root(3),
    });
    ops.push(Operation::AssertPayloadWeights {
        block_root: get_root(3),
        expected_full_weight: 1,
        expected_empty_weight: 0,
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

pub fn get_gloas_weight_priority_over_payload_preference_test_definition()
-> ForkChoiceTestDefinition {
    let mut ops = vec![];

    // Build two branches where one child extends payload (Full) and the other doesn't (Empty).
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

    // Parent prefers Full on equal branch weights.
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

    // Add two Empty votes to make the Empty branch strictly heavier.
    ops.push(Operation::ProcessPayloadAttestation {
        validator_index: 0,
        block_root: get_root(4),
        attestation_slot: Slot::new(3),
        payload_present: false,
        blob_data_available: false,
    });
    ops.push(Operation::ProcessPayloadAttestation {
        validator_index: 1,
        block_root: get_root(4),
        attestation_slot: Slot::new(3),
        payload_present: false,
        blob_data_available: false,
    });
    ops.push(Operation::FindHead {
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        justified_state_balances: vec![1, 1],
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

pub fn get_gloas_parent_empty_when_child_points_to_grandparent_test_definition()
-> ForkChoiceTestDefinition {
    let mut ops = vec![];

    // Build a three-block chain A -> B -> C (CL parent links).
    // A: EL parent = genesis hash(0), EL hash = hash(1).
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(1),
        root: get_root(1),
        parent_root: get_root(0),
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        execution_payload_parent_hash: Some(get_hash(0)),
        execution_payload_block_hash: Some(get_hash(1)),
    });

    // B: EL parent = hash(1), EL hash = hash(2).
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(2),
        root: get_root(2),
        parent_root: get_root(1),
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        execution_payload_parent_hash: Some(get_hash(1)),
        execution_payload_block_hash: Some(get_hash(2)),
    });

    // C: CL parent is B, but EL parent points to A (hash 1), not B (hash 2).
    // This models B's payload not arriving in time, so C records parent status as Empty.
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(3),
        root: get_root(3),
        parent_root: get_root(2),
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        execution_payload_parent_hash: Some(get_hash(1)),
        execution_payload_block_hash: Some(get_hash(3)),
    });

    ops.push(Operation::AssertParentPayloadStatus {
        block_root: get_root(3),
        expected_status: PayloadStatus::Empty,
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

    #[test]
    fn find_head_vote_transition() {
        let test = get_gloas_find_head_vote_transition_test_definition();
        test.run();
    }

    #[test]
    fn weight_priority_over_payload_preference() {
        let test = get_gloas_weight_priority_over_payload_preference_test_definition();
        test.run();
    }

    #[test]
    fn parent_empty_when_child_points_to_grandparent() {
        let test = get_gloas_parent_empty_when_child_points_to_grandparent_test_definition();
        test.run();
    }
}
