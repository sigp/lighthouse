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
    // its FULL virtual node exists in the Gloas fork choice tree.
    ops.push(Operation::ProcessExecutionPayloadEnvelope {
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
        expected_payload_status: None,
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
        expected_payload_status: None,
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

    // Block 1 at slot 1: child of genesis. Genesis has execution_payload_block_hash=zero
    // (no execution payload at genesis), so all children have parent_payload_status=Empty.
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
        current_slot: Slot::new(0),
        // With MainnetEthSpec PTC_SIZE=512, 1 bit set out of 256 threshold → not timely → Empty.
        expected_payload_status: Some(PayloadStatus::Empty),
    });
    // PTC votes write to bitfields only, not to full/empty weight.
    // Weight is 0 because no CL attestations target this block.
    ops.push(Operation::AssertPayloadWeights {
        block_root: get_root(1),
        expected_full_weight: 0,
        expected_empty_weight: 0,
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
        expected_payload_status: Some(PayloadStatus::Empty),
    });
    ops.push(Operation::AssertPayloadWeights {
        block_root: get_root(1),
        expected_full_weight: 0,
        expected_empty_weight: 0,
    });

    // Same-slot attestation to a new head candidate should be Pending (no payload bucket change).
    // Root 5 is an Empty child of root_1 (parent_hash doesn't match root_1's block_hash),
    // so it's reachable through root_1's Empty direction (root_1 has no payload_received).
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(3),
        root: get_root(5),
        parent_root: get_root(1),
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        execution_payload_parent_hash: Some(get_hash(101)),
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
        expected_payload_status: Some(PayloadStatus::Empty),
    });
    ops.push(Operation::AssertPayloadWeights {
        block_root: get_root(5),
        expected_full_weight: 0,
        expected_empty_weight: 0,
    });

    ForkChoiceTestDefinition {
        finalized_block_slot: Slot::new(0),
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        operations: ops,
        // Genesis has zero execution block hash (no payload at genesis), which
        // ensures all children get parent_payload_status=Empty.
        execution_payload_parent_hash: Some(ExecutionBlockHash::zero()),
        execution_payload_block_hash: Some(ExecutionBlockHash::zero()),
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
    // its FULL virtual node exists in the Gloas fork choice tree.
    ops.push(Operation::ProcessExecutionPayloadEnvelope {
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
        expected_payload_status: None,
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
        expected_payload_status: None,
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
        expected_payload_status: None,
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
    // its FULL virtual node exists in the Gloas fork choice tree.
    ops.push(Operation::ProcessExecutionPayloadEnvelope {
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
        expected_payload_status: None,
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
        expected_payload_status: None,
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
    // its FULL virtual node exists in the Gloas fork choice tree.
    ops.push(Operation::ProcessExecutionPayloadEnvelope {
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
        expected_payload_status: None,
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
        expected_payload_status: None,
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
        expected_payload_status: None,
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
/// Scenario (branching at block 1 since genesis has no payload):
///   - Genesis block (slot 0) with zero execution block hash
///   - Block 1 (slot 1) child of genesis (Empty parent status since genesis hash=zero)
///   - Block 2 (slot 2) extends block 1 Full chain (parent_hash matches block 1's block_hash)
///   - Block 3 (slot 2) extends block 1 Empty chain (parent_hash doesn't match)
///   - Before payload arrives: payload_received is false for block 1, only Empty reachable
///   - Process execution payload for block 1 → payload_received becomes true
///   - Both Full and Empty directions from block 1 become available
///   - With equal weight, tiebreaker prefers Full → Block 2 wins
pub fn get_gloas_payload_received_interleaving_test_definition() -> ForkChoiceTestDefinition {
    let mut ops = vec![];

    // Block 1 at slot 1: child of genesis. Genesis has zero block hash, so
    // parent_payload_status = Empty regardless of block 1's execution_payload_parent_hash.
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(1),
        root: get_root(1),
        parent_root: get_root(0),
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        execution_payload_parent_hash: Some(get_hash(0)),
        execution_payload_block_hash: Some(get_hash(1)),
    });

    // Block 2 at slot 2: Full child of block 1 (parent_hash matches block 1's block_hash).
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(2),
        root: get_root(2),
        parent_root: get_root(1),
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        execution_payload_parent_hash: Some(get_hash(1)),
        execution_payload_block_hash: Some(get_hash(2)),
    });

    // Block 3 at slot 2: Empty child of block 1 (parent_hash doesn't match block 1's block_hash).
    ops.push(Operation::ProcessBlock {
        slot: Slot::new(2),
        root: get_root(3),
        parent_root: get_root(1),
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        execution_payload_parent_hash: Some(get_hash(99)),
        execution_payload_block_hash: Some(get_hash(3)),
    });

    // Verify parent_payload_status is set correctly.
    ops.push(Operation::AssertParentPayloadStatus {
        block_root: get_root(1),
        expected_status: PayloadStatus::Empty,
    });
    ops.push(Operation::AssertParentPayloadStatus {
        block_root: get_root(2),
        expected_status: PayloadStatus::Full,
    });
    ops.push(Operation::AssertParentPayloadStatus {
        block_root: get_root(3),
        expected_status: PayloadStatus::Empty,
    });

    // Genesis does NOT have payload_received (no payload at genesis).
    ops.push(Operation::AssertPayloadReceived {
        block_root: get_root(0),
        expected: false,
    });

    // Block 1 does not have payload_received yet.
    ops.push(Operation::AssertPayloadReceived {
        block_root: get_root(1),
        expected: false,
    });

    // Give one vote to each competing child so they have equal weight.
    ops.push(Operation::ProcessAttestation {
        validator_index: 0,
        block_root: get_root(2),
        attestation_slot: Slot::new(2),
    });
    ops.push(Operation::ProcessAttestation {
        validator_index: 1,
        block_root: get_root(3),
        attestation_slot: Slot::new(2),
    });

    // Before payload_received on block 1: only Empty direction available.
    // Block 3 (Empty child) is reachable, Block 2 (Full child) is not.
    ops.push(Operation::FindHead {
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        justified_state_balances: vec![1, 1],
        expected_head: get_root(3),
        current_slot: Slot::new(100),
        expected_payload_status: None,
    });

    // Process execution payload envelope for block 1 → payload_received becomes true.
    ops.push(Operation::ProcessExecutionPayloadEnvelope {
        block_root: get_root(1),
    });

    ops.push(Operation::AssertPayloadReceived {
        block_root: get_root(1),
        expected: true,
    });

    // After payload_received on block 1: both Full and Empty directions available.
    // Equal weight, tiebreaker prefers Full → Block 2 (Full child) wins.
    ops.push(Operation::FindHead {
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        justified_state_balances: vec![1, 1],
        expected_head: get_root(2),
        current_slot: Slot::new(100),
        expected_payload_status: None,
    });

    ForkChoiceTestDefinition {
        finalized_block_slot: Slot::new(0),
        justified_checkpoint: get_checkpoint(0),
        finalized_checkpoint: get_checkpoint(0),
        operations: ops,
        // Genesis has zero execution block hash (no payload at genesis).
        execution_payload_parent_hash: Some(ExecutionBlockHash::zero()),
        execution_payload_block_hash: Some(ExecutionBlockHash::zero()),
        spec: Some(gloas_spec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gloas_fork_boundary_spec() -> ChainSpec {
        let mut spec = MainnetEthSpec::default_spec();
        spec.proposer_score_boost = Some(50);
        spec.gloas_fork_epoch = Some(Epoch::new(1));
        spec
    }

    /// Gloas fork boundary: a chain starting pre-Gloas (V17 nodes) that crosses into
    /// Gloas (V29 nodes). The head should advance through the fork boundary.
    ///
    /// Parameters:
    /// - `skip_first_gloas_slot`: if true, there is no block at the first Gloas slot (slot 32);
    ///   the first V29 block appears at slot 33.
    /// - `first_gloas_block_full`: if true, the first V29 block extends the parent V17 node's
    ///   EL chain (Full parent payload status). If false, it doesn't (Empty).
    fn get_gloas_fork_boundary_test_definition(
        skip_first_gloas_slot: bool,
        first_gloas_block_full: bool,
    ) -> ForkChoiceTestDefinition {
        let mut ops = vec![];

        // Block at slot 31 — last pre-Gloas slot. Created as a V17 node because
        // gloas_fork_epoch = 1 → Gloas starts at slot 32.
        //
        // The test harness sets execution_status = Optimistic(ExecutionBlockHash::from_root(root)),
        // so this V17 node's EL block hash = ExecutionBlockHash::from_root(get_root(1)).
        ops.push(Operation::ProcessBlock {
            slot: Slot::new(31),
            root: get_root(1),
            parent_root: get_root(0),
            justified_checkpoint: get_checkpoint(0),
            finalized_checkpoint: get_checkpoint(0),
            execution_payload_parent_hash: None,
            execution_payload_block_hash: None,
        });

        // First Gloas block (V29 node).
        let gloas_slot = if skip_first_gloas_slot { 33 } else { 32 };

        // The first Gloas block should always have the pre-Gloas block as its execution parent,
        // although this is currently not checked anywhere (the spec doesn't mention this).
        ops.push(Operation::ProcessBlock {
            slot: Slot::new(gloas_slot),
            root: get_root(2),
            parent_root: get_root(1),
            justified_checkpoint: get_checkpoint(0),
            finalized_checkpoint: get_checkpoint(0),
            execution_payload_parent_hash: Some(get_hash(1)),
            execution_payload_block_hash: Some(get_hash(2)),
        });

        // Parent payload status of fork boundary block should always be Empty.
        let expected_parent_status = PayloadStatus::Empty;
        ops.push(Operation::AssertParentPayloadStatus {
            block_root: get_root(2),
            expected_status: expected_parent_status,
        });

        // Mark root 2's execution payload as received so the Full virtual child exists.
        if first_gloas_block_full {
            ops.push(Operation::ProcessExecutionPayloadEnvelope {
                block_root: get_root(2),
            });
        }

        // Extend the chain with another V29 block (Full child of root 2).
        ops.push(Operation::ProcessBlock {
            slot: Slot::new(gloas_slot + 1),
            root: get_root(3),
            parent_root: get_root(2),
            justified_checkpoint: get_checkpoint(0),
            finalized_checkpoint: get_checkpoint(0),
            execution_payload_parent_hash: if first_gloas_block_full {
                Some(get_hash(2))
            } else {
                Some(get_hash(1))
            },
            execution_payload_block_hash: Some(get_hash(3)),
        });

        // Head should advance to the tip of the chain through the fork boundary.
        ops.push(Operation::FindHead {
            justified_checkpoint: get_checkpoint(0),
            finalized_checkpoint: get_checkpoint(0),
            justified_state_balances: vec![1],
            expected_head: get_root(3),
            current_slot: Slot::new(gloas_slot + 1),
            expected_payload_status: None,
        });

        ops.push(Operation::AssertParentPayloadStatus {
            block_root: get_root(3),
            expected_status: if first_gloas_block_full {
                PayloadStatus::Full
            } else {
                PayloadStatus::Empty
            },
        });

        ForkChoiceTestDefinition {
            finalized_block_slot: Slot::new(0),
            justified_checkpoint: get_checkpoint(0),
            finalized_checkpoint: get_checkpoint(0),
            operations: ops,
            // Genesis is V17 (slot 0 < Gloas fork slot 32), these are unused for V17.
            execution_payload_parent_hash: None,
            execution_payload_block_hash: None,
            spec: Some(gloas_fork_boundary_spec()),
        }
    }

    #[test]
    fn fork_boundary_no_skip_full() {
        get_gloas_fork_boundary_test_definition(false, true).run();
    }

    #[test]
    fn fork_boundary_no_skip_empty() {
        get_gloas_fork_boundary_test_definition(false, false).run();
    }

    #[test]
    fn fork_boundary_skip_first_gloas_slot_full() {
        get_gloas_fork_boundary_test_definition(true, true).run();
    }

    #[test]
    fn fork_boundary_skip_first_gloas_slot_empty() {
        get_gloas_fork_boundary_test_definition(true, false).run();
    }

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

    /// Test that execution payload invalidation propagates across the V17→V29 fork
    /// boundary: after invalidating a V17 parent, head must not select any descendant.
    ///
    ///   genesis(V17) -> block_1(V17, slot 31) -> block_2(V29, slot 32)
    #[test]
    fn mixed_v17_v29_invalidation() {
        let balances = vec![1];
        let mut ops = vec![];

        // V17 block at slot 31 (pre-Gloas).
        ops.push(Operation::ProcessBlock {
            slot: Slot::new(31),
            root: get_root(1),
            parent_root: get_root(0),
            justified_checkpoint: get_checkpoint(0),
            finalized_checkpoint: get_checkpoint(0),
            execution_payload_parent_hash: None,
            execution_payload_block_hash: None,
        });

        // V29 block at slot 32 (first Gloas slot), child of block 1.
        ops.push(Operation::ProcessBlock {
            slot: Slot::new(32),
            root: get_root(2),
            parent_root: get_root(1),
            justified_checkpoint: get_checkpoint(0),
            finalized_checkpoint: get_checkpoint(0),
            execution_payload_parent_hash: Some(get_hash(1)),
            execution_payload_block_hash: Some(get_hash(2)),
        });

        // Vote for block 2 (V29) so both blocks have weight.
        ops.push(Operation::ProcessAttestation {
            validator_index: 0,
            block_root: get_root(2),
            attestation_slot: Slot::new(32),
        });

        // FindHead triggers apply_score_changes which materializes the vote.
        ops.push(Operation::FindHead {
            justified_checkpoint: get_checkpoint(0),
            finalized_checkpoint: get_checkpoint(0),
            justified_state_balances: balances.clone(),
            expected_head: get_root(2),
            current_slot: Slot::new(32),
            expected_payload_status: None,
        });

        // Invalidate block 1 (V17). filter_block_tree excludes the entire branch.
        ops.push(Operation::InvalidatePayload {
            head_block_root: get_root(1),
            latest_valid_ancestor_root: Some(get_hash(0)),
        });

        // Head falls back to genesis — the invalid branch is no longer selectable.
        ops.push(Operation::FindHead {
            justified_checkpoint: get_checkpoint(0),
            finalized_checkpoint: get_checkpoint(0),
            justified_state_balances: balances.clone(),
            expected_head: get_root(0),
            current_slot: Slot::new(32),
            expected_payload_status: None,
        });

        ForkChoiceTestDefinition {
            finalized_block_slot: Slot::new(0),
            justified_checkpoint: get_checkpoint(0),
            finalized_checkpoint: get_checkpoint(0),
            operations: ops,
            execution_payload_parent_hash: None,
            execution_payload_block_hash: None,
            spec: Some(gloas_fork_boundary_spec()),
        }
        .run();
    }
}
