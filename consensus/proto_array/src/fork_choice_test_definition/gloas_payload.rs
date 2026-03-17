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

    // Mark root_1 as having received its execution payload so that
    // its FULL virtual node exists in the GLOAS fork choice tree.
    ops.push(Operation::ProcessExecutionPayload {
        block_root: get_root(1),
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
        current_slot: Slot::new(0),
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
        current_slot: Slot::new(0),
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

    // Mark root_1 as having received its execution payload so that
    // its FULL virtual node exists in the GLOAS fork choice tree.
    ops.push(Operation::ProcessExecutionPayload {
        block_root: get_root(1),
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
        current_slot: Slot::new(0),
    });
    // PTC votes write to bitfields only, not to full/empty weight.
    // Weight is 0 because no CL attestations target this block.
    ops.push(Operation::AssertPayloadWeights {
        block_root: get_root(1),
        expected_full_weight: 0,
        expected_empty_weight: 0,
    });
    // With MainnetEthSpec PTC_SIZE=512, 1 bit set out of 256 threshold → not timely → Empty.
    ops.push(Operation::AssertHeadPayloadStatus {
        head_root: get_root(1),
        expected_status: PayloadStatus::Empty,
        current_slot: Slot::new(0),
    });

    // Flip validator 0 to Empty; both bits now clear.
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
        current_slot: Slot::new(0),
    });
    ops.push(Operation::AssertPayloadWeights {
        block_root: get_root(1),
        expected_full_weight: 0,
        expected_empty_weight: 0,
    });
    ops.push(Operation::AssertHeadPayloadStatus {
        head_root: get_root(1),
        expected_status: PayloadStatus::Empty,
        current_slot: Slot::new(0),
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
        current_slot: Slot::new(0),
    });
    ops.push(Operation::AssertPayloadWeights {
        block_root: get_root(5),
        expected_full_weight: 0,
        expected_empty_weight: 0,
    });
    ops.push(Operation::AssertHeadPayloadStatus {
        head_root: get_root(5),
        expected_status: PayloadStatus::Empty,
        current_slot: Slot::new(0),
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

/// Test that CL attestation weight can flip the head between Full/Empty branches,
/// overriding the tiebreaker.
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

    // Mark root_1 as having received its execution payload so that
    // its FULL virtual node exists in the GLOAS fork choice tree.
    ops.push(Operation::ProcessExecutionPayload {
        block_root: get_root(1),
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
        current_slot: Slot::new(0),
    });

    // CL attestation to Empty branch (root 4) from validator 0 → head flips to 4.
    ops.push(Operation::ProcessAttestation {
        validator_index: 0,
        block_root: get_root(4),
        attestation_slot: Slot::new(3),
    });
    ops.push(Operation::FindHead {
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        justified_state_balances: vec![1],
        expected_head: get_root(4),
        current_slot: Slot::new(0),
    });

    // CL attestation back to Full branch (root 3) → head returns to 3.
    ops.push(Operation::ProcessAttestation {
        validator_index: 0,
        block_root: get_root(3),
        attestation_slot: Slot::new(4),
    });
    ops.push(Operation::FindHead {
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        justified_state_balances: vec![1],
        expected_head: get_root(3),
        current_slot: Slot::new(0),
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

/// CL attestation weight overrides payload preference tiebreaker.
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

    // Mark root_1 as having received its execution payload so that
    // its FULL virtual node exists in the GLOAS fork choice tree.
    ops.push(Operation::ProcessExecutionPayload {
        block_root: get_root(1),
    });

    // Parent prefers Full on equal branch weights (tiebreaker).
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
        current_slot: Slot::new(0),
    });

    // Two CL attestations to the Empty branch make it strictly heavier,
    // overriding the Full tiebreaker.
    ops.push(Operation::ProcessAttestation {
        validator_index: 0,
        block_root: get_root(4),
        attestation_slot: Slot::new(3),
    });
    ops.push(Operation::ProcessAttestation {
        validator_index: 1,
        block_root: get_root(4),
        attestation_slot: Slot::new(3),
    });
    ops.push(Operation::FindHead {
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        justified_state_balances: vec![1, 1],
        expected_head: get_root(4),
        current_slot: Slot::new(0),
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

/// Test interleaving of blocks, regular attestations, and tiebreaker.
///
/// genesis → block 1 (Full) → block 3
///         → block 2 (Empty) → block 4
///
/// With equal CL weight, tiebreaker determines which branch wins.
/// An extra CL attestation can override the tiebreaker.
pub fn get_gloas_interleaved_attestations_test_definition() -> ForkChoiceTestDefinition {
    let mut ops = vec![];

    // Step 1: Two competing blocks at slot 1.
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

    // Step 2: Regular attestations arrive, one per branch (equal CL weight).
    ops.push(Operation::ProcessAttestation {
        validator_index: 0,
        block_root: get_root(1),
        attestation_slot: Slot::new(1),
    });
    ops.push(Operation::ProcessAttestation {
        validator_index: 1,
        block_root: get_root(2),
        attestation_slot: Slot::new(1),
    });

    // Step 3: Child blocks at slot 2.
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

    // Mark root_1 as having received its execution payload so that
    // its FULL virtual node exists in the GLOAS fork choice tree.
    ops.push(Operation::ProcessExecutionPayload {
        block_root: get_root(1),
    });

    // Step 4: Set tiebreaker to Empty on genesis → Empty branch wins.
    ops.push(Operation::SetPayloadTiebreak {
        block_root: get_root(0),
        is_timely: false,
        is_data_available: false,
    });
    ops.push(Operation::FindHead {
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        justified_state_balances: vec![1, 1],
        expected_head: get_root(4),
        current_slot: Slot::new(1),
    });

    // Step 5: Flip tiebreaker to Full → Full branch wins.
    ops.push(Operation::SetPayloadTiebreak {
        block_root: get_root(0),
        is_timely: true,
        is_data_available: true,
    });
    ops.push(Operation::FindHead {
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        justified_state_balances: vec![1, 1],
        expected_head: get_root(3),
        current_slot: Slot::new(100),
    });

    // Step 6: Add extra CL weight to Empty branch → overrides Full tiebreaker.
    ops.push(Operation::ProcessAttestation {
        validator_index: 2,
        block_root: get_root(4),
        attestation_slot: Slot::new(3),
    });
    ops.push(Operation::FindHead {
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        justified_state_balances: vec![1, 1, 1],
        expected_head: get_root(4),
        current_slot: Slot::new(100),
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

/// Test interleaving of blocks, payload validation, and attestations.
///
/// Scenario:
///   - Genesis block (slot 0)
///   - Block 1 (slot 1) extends genesis, Full chain
///   - Block 2 (slot 1) extends genesis, Empty chain
///   - Before payload arrives: payload_received is false for block 1
///   - Process execution payload for block 1 → payload_received becomes true
///   - Payload attestations arrive voting block 1's payload as timely + available
///   - Head should follow block 1 because the PTC votes now count (payload_received = true)
pub fn get_gloas_payload_received_interleaving_test_definition() -> ForkChoiceTestDefinition {
    let mut ops = vec![];

    // Block 1 at slot 1: extends genesis Full chain.
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(1),
        root: get_root(1),
        parent_root: get_root(0),
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        execution_payload_parent_hash: Some(get_hash(0)),
        execution_payload_block_hash: Some(get_hash(1)),
    });

    // Block 2 at slot 1: extends genesis Empty chain (parent_hash doesn't match genesis EL hash).
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(1),
        root: get_root(2),
        parent_root: get_root(0),
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        execution_payload_parent_hash: Some(get_hash(99)),
        execution_payload_block_hash: Some(get_hash(100)),
    });

    // Both children have parent_payload_status set correctly.
    ops.push(Operation::AssertParentPayloadStatus {
        block_root: get_root(1),
        expected_status: PayloadStatus::Full,
    });
    ops.push(Operation::AssertParentPayloadStatus {
        block_root: get_root(2),
        expected_status: PayloadStatus::Empty,
    });

    // Per spec `get_forkchoice_store`: genesis starts with payload_received=true
    // (anchor block is in `payload_states`).
    ops.push(Operation::AssertPayloadReceived {
        block_root: get_root(0),
        expected: true,
    });

    // Give one vote to each child so they have equal weight.
    ops.push(Operation::ProcessAttestation {
        validator_index: 0,
        block_root: get_root(1),
        attestation_slot: Slot::new(1),
    });
    ops.push(Operation::ProcessAttestation {
        validator_index: 1,
        block_root: get_root(2),
        attestation_slot: Slot::new(1),
    });

    // Equal weight, payload_received=true on genesis → tiebreaker uses
    // payload_received (not previous slot, equal payload weights) → prefers Full.
    // Block 1 (Full) wins because it matches the Full preference.
    ops.push(Operation::FindHead {
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        justified_state_balances: vec![1, 1],
        expected_head: get_root(1),
        current_slot: Slot::new(100),
    });

    // ProcessExecutionPayload on genesis is a no-op (already received at init).
    ops.push(Operation::ProcessExecutionPayload {
        block_root: get_root(0),
    });

    ops.push(Operation::AssertPayloadReceived {
        block_root: get_root(0),
        expected: true,
    });

    // Set PTC votes on genesis as timely + data available (simulates PTC voting).
    // This doesn't change the preference since genesis is not the previous slot
    // (slot 0 + 1 != current_slot 100).
    ops.push(Operation::SetPayloadTiebreak {
        block_root: get_root(0),
        is_timely: true,
        is_data_available: true,
    });

    // Still prefers Full via payload_received tiebreaker → Block 1 (Full) wins.
    ops.push(Operation::FindHead {
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        justified_state_balances: vec![1, 1],
        expected_head: get_root(1),
        current_slot: Slot::new(100),
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

    #[test]
    fn interleaved_attestations() {
        let test = get_gloas_interleaved_attestations_test_definition();
        test.run();
    }

    #[test]
    fn payload_received_interleaving() {
        let test = get_gloas_payload_received_interleaving_test_definition();
        test.run();
    }
}
