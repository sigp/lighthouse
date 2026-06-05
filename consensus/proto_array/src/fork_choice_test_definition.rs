mod execution_status;
mod ffg_updates;
mod gloas_payload;
mod no_votes;
mod votes;

use crate::error::Error;
use crate::proto_array_fork_choice::{Block, ExecutionStatus, PayloadStatus, ProtoArrayForkChoice};
use crate::{InvalidationOperation, JustifiedBalances};
use fixed_bytes::FixedBytesExtended;
use serde::{Deserialize, Serialize};
use ssz::BitVector;
use std::collections::BTreeSet;
use std::time::Duration;
use types::{
    AttestationShufflingId, ChainSpec, Checkpoint, Epoch, EthSpec, ExecutionBlockHash, Hash256,
    MainnetEthSpec, Slot,
};

pub use execution_status::*;
pub use ffg_updates::*;
pub use gloas_payload::*;
pub use no_votes::*;
pub use votes::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operation {
    FindHead {
        justified_checkpoint: Checkpoint,
        finalized_checkpoint: Checkpoint,
        justified_state_balances: Vec<u64>,
        expected_head: Hash256,
        current_slot: Slot,
        // TODO(gloas): Make this non-optional. `find_head` always returns a `PayloadStatus`
        // (Empty for pre-GLOAS), so every test should assert on it explicitly.
        #[serde(default)]
        expected_payload_status: Option<PayloadStatus>,
    },
    ProposerBoostFindHead {
        justified_checkpoint: Checkpoint,
        finalized_checkpoint: Checkpoint,
        justified_state_balances: Vec<u64>,
        expected_head: Hash256,
        proposer_boost_root: Hash256,
    },
    InvalidFindHead {
        justified_checkpoint: Checkpoint,
        finalized_checkpoint: Checkpoint,
        justified_state_balances: Vec<u64>,
    },
    ProcessBlock {
        slot: Slot,
        root: Hash256,
        parent_root: Hash256,
        justified_checkpoint: Checkpoint,
        finalized_checkpoint: Checkpoint,
        #[serde(default)]
        execution_payload_parent_hash: Option<ExecutionBlockHash>,
        #[serde(default)]
        execution_payload_block_hash: Option<ExecutionBlockHash>,
    },
    ProcessAttestation {
        validator_index: usize,
        block_root: Hash256,
        attestation_slot: Slot,
    },
    ProcessGloasAttestation {
        validator_index: usize,
        block_root: Hash256,
        attestation_slot: Slot,
        payload_present: bool,
    },
    ProcessPayloadAttestation {
        validator_index: usize,
        block_root: Hash256,
        attestation_slot: Slot,
        payload_present: bool,
        #[serde(default)]
        blob_data_available: bool,
    },
    Prune {
        finalized_root: Hash256,
        prune_threshold: usize,
        expected_len: usize,
    },
    InvalidatePayload {
        head_block_root: Hash256,
        latest_valid_ancestor_root: Option<ExecutionBlockHash>,
    },
    AssertWeight {
        block_root: Hash256,
        weight: u64,
    },
    AssertPayloadWeights {
        block_root: Hash256,
        expected_full_weight: u64,
        expected_empty_weight: u64,
    },
    AssertParentPayloadStatus {
        block_root: Hash256,
        expected_status: PayloadStatus,
    },
    SetPayloadTiebreak {
        block_root: Hash256,
        is_timely: bool,
        is_data_available: bool,
    },
    /// Simulate receiving and validating an execution payload for `block_root`.
    /// Sets `payload_received = true` on the V29 node via the live validation path.
    ProcessExecutionPayloadEnvelope {
        block_root: Hash256,
    },
    AssertPayloadReceived {
        block_root: Hash256,
        expected: bool,
    },
    AssertPayloadStatusByWeight {
        block_root: Hash256,
        expected_status: PayloadStatus,
        /// Override `current_slot`. Defaults to the `current_slot` of the last `FindHead`.
        #[serde(default)]
        current_slot: Option<Slot>,
        /// Override the proposer boost root. Defaults to `Hash256::zero()`.
        #[serde(default)]
        proposer_boost_root: Option<Hash256>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkChoiceTestDefinition {
    pub finalized_block_slot: Slot,
    pub justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
    pub operations: Vec<Operation>,
    #[serde(default)]
    pub execution_payload_parent_hash: Option<ExecutionBlockHash>,
    #[serde(default)]
    pub execution_payload_block_hash: Option<ExecutionBlockHash>,
    #[serde(skip)]
    pub spec: Option<ChainSpec>,
}

impl ForkChoiceTestDefinition {
    pub fn run(self) {
        let spec = self.spec.unwrap_or_else(|| {
            let mut spec = MainnetEthSpec::default_spec();
            spec.proposer_score_boost = 50;
            // Legacy test definitions target pre-Gloas behaviour unless explicitly overridden.
            spec.gloas_fork_epoch = None;
            spec
        });

        let junk_shuffling_id =
            AttestationShufflingId::from_components(Epoch::new(0), Hash256::zero());
        let mut fork_choice = ProtoArrayForkChoice::new::<MainnetEthSpec>(
            self.finalized_block_slot,
            self.finalized_block_slot,
            Hash256::zero(),
            self.justified_checkpoint,
            self.finalized_checkpoint,
            junk_shuffling_id.clone(),
            junk_shuffling_id,
            ExecutionStatus::Optimistic(ExecutionBlockHash::zero()),
            self.execution_payload_parent_hash,
            self.execution_payload_block_hash,
            0,
            &spec,
        )
        .expect("should create fork choice struct");
        let equivocating_indices = BTreeSet::new();
        let mut last_current_slot = Slot::new(0);

        for (op_index, op) in self.operations.into_iter().enumerate() {
            match op.clone() {
                Operation::FindHead {
                    justified_checkpoint,
                    finalized_checkpoint,
                    justified_state_balances,
                    expected_head,
                    current_slot,
                    expected_payload_status,
                } => {
                    let justified_balances =
                        JustifiedBalances::from_effective_balances(justified_state_balances)
                            .unwrap();
                    let (head, payload_status) = fork_choice
                        .find_head::<MainnetEthSpec>(
                            justified_checkpoint,
                            finalized_checkpoint,
                            &justified_balances,
                            Hash256::zero(),
                            &equivocating_indices,
                            current_slot,
                            &spec,
                        )
                        .unwrap_or_else(|e| {
                            panic!("find_head op at index {} returned error {}", op_index, e)
                        });

                    assert_eq!(
                        head, expected_head,
                        "Operation at index {} failed head check. Operation: {:?}",
                        op_index, op
                    );
                    if let Some(expected_status) = expected_payload_status {
                        assert_eq!(
                            payload_status, expected_status,
                            "Operation at index {} failed payload status check. Operation: {:?}",
                            op_index, op
                        );
                    }
                    assert_canonical_payload_status_matches_find_head(
                        &fork_choice,
                        &head,
                        current_slot,
                        Hash256::zero(),
                        &spec,
                        payload_status,
                        op_index,
                    );
                    last_current_slot = current_slot;
                    check_bytes_round_trip(&fork_choice);
                }
                Operation::ProposerBoostFindHead {
                    justified_checkpoint,
                    finalized_checkpoint,
                    justified_state_balances,
                    expected_head,
                    proposer_boost_root,
                } => {
                    let justified_balances =
                        JustifiedBalances::from_effective_balances(justified_state_balances)
                            .unwrap();
                    let (head, payload_status) = fork_choice
                        .find_head::<MainnetEthSpec>(
                            justified_checkpoint,
                            finalized_checkpoint,
                            &justified_balances,
                            proposer_boost_root,
                            &equivocating_indices,
                            Slot::new(0),
                            &spec,
                        )
                        .unwrap_or_else(|e| {
                            panic!("find_head op at index {} returned error {}", op_index, e)
                        });

                    assert_eq!(
                        head, expected_head,
                        "Operation at index {} failed head check. Operation: {:?}",
                        op_index, op
                    );
                    assert_canonical_payload_status_matches_find_head(
                        &fork_choice,
                        &head,
                        Slot::new(0),
                        proposer_boost_root,
                        &spec,
                        payload_status,
                        op_index,
                    );
                    check_bytes_round_trip(&fork_choice);
                }
                Operation::InvalidFindHead {
                    justified_checkpoint,
                    finalized_checkpoint,
                    justified_state_balances,
                } => {
                    let justified_balances =
                        JustifiedBalances::from_effective_balances(justified_state_balances)
                            .unwrap();
                    let result = fork_choice.find_head::<MainnetEthSpec>(
                        justified_checkpoint,
                        finalized_checkpoint,
                        &justified_balances,
                        Hash256::zero(),
                        &equivocating_indices,
                        Slot::new(0),
                        &spec,
                    );

                    assert!(
                        result.is_err(),
                        "Operation at index {} . Operation: {:?}",
                        op_index,
                        op
                    );
                    check_bytes_round_trip(&fork_choice);
                }
                Operation::ProcessBlock {
                    slot,
                    root,
                    parent_root,
                    justified_checkpoint,
                    finalized_checkpoint,
                    execution_payload_parent_hash,
                    execution_payload_block_hash,
                } => {
                    let block = Block {
                        slot,
                        root,
                        parent_root: Some(parent_root),
                        state_root: Hash256::zero(),
                        target_root: Hash256::zero(),
                        current_epoch_shuffling_id: AttestationShufflingId::from_components(
                            Epoch::new(0),
                            Hash256::zero(),
                        ),
                        next_epoch_shuffling_id: AttestationShufflingId::from_components(
                            Epoch::new(0),
                            Hash256::zero(),
                        ),
                        justified_checkpoint,
                        finalized_checkpoint,
                        // All blocks are imported optimistically.
                        execution_status: ExecutionStatus::Optimistic(
                            ExecutionBlockHash::from_root(root),
                        ),
                        unrealized_justified_checkpoint: None,
                        unrealized_finalized_checkpoint: None,
                        execution_payload_parent_hash,
                        execution_payload_block_hash,
                        proposer_index: Some(0),
                    };
                    fork_choice
                        .process_block::<MainnetEthSpec>(block, slot, &spec, Duration::ZERO)
                        .unwrap_or_else(|e| {
                            panic!(
                                "process_block op at index {} returned error: {:?}",
                                op_index, e
                            )
                        });
                    check_bytes_round_trip(&fork_choice);
                }
                Operation::ProcessAttestation {
                    validator_index,
                    block_root,
                    attestation_slot,
                } => {
                    fork_choice
                        .process_attestation(validator_index, block_root, attestation_slot, false)
                        .unwrap_or_else(|_| {
                            panic!(
                                "process_attestation op at index {} returned error",
                                op_index
                            )
                        });
                    check_bytes_round_trip(&fork_choice);
                }
                Operation::ProcessGloasAttestation {
                    validator_index,
                    block_root,
                    attestation_slot,
                    payload_present,
                } => {
                    fork_choice
                        .process_attestation(
                            validator_index,
                            block_root,
                            attestation_slot,
                            payload_present,
                        )
                        .unwrap_or_else(|_| {
                            panic!(
                                "process_attestation op at index {} returned error",
                                op_index
                            )
                        });
                    check_bytes_round_trip(&fork_choice);
                }
                Operation::ProcessPayloadAttestation {
                    validator_index,
                    block_root,
                    attestation_slot: _,
                    payload_present,
                    blob_data_available,
                } => {
                    fork_choice
                        .process_payload_attestation(
                            block_root,
                            validator_index,
                            payload_present,
                            blob_data_available,
                        )
                        .unwrap_or_else(|_| {
                            panic!(
                                "process_payload_attestation op at index {} returned error",
                                op_index
                            )
                        });
                    check_bytes_round_trip(&fork_choice);
                }
                Operation::Prune {
                    finalized_root,
                    prune_threshold,
                    expected_len,
                } => {
                    fork_choice.set_prune_threshold(prune_threshold);
                    fork_choice
                        .maybe_prune(finalized_root)
                        .expect("update_finalized_root op at index {} returned error");

                    // Ensure that no pruning happened.
                    assert_eq!(
                        fork_choice.len(),
                        expected_len,
                        "Prune op at index {} failed with {} instead of {}",
                        op_index,
                        fork_choice.len(),
                        expected_len
                    );
                }
                Operation::InvalidatePayload {
                    head_block_root,
                    latest_valid_ancestor_root,
                } => {
                    let op = if let Some(latest_valid_ancestor) = latest_valid_ancestor_root {
                        InvalidationOperation::InvalidateMany {
                            head_block_root,
                            always_invalidate_head: true,
                            latest_valid_ancestor,
                        }
                    } else {
                        InvalidationOperation::InvalidateOne {
                            block_root: head_block_root,
                        }
                    };
                    fork_choice
                        .process_execution_payload_invalidation::<MainnetEthSpec>(
                            &op,
                            self.finalized_checkpoint,
                        )
                        .unwrap()
                }
                Operation::AssertWeight { block_root, weight } => assert_eq!(
                    fork_choice.get_weight(&block_root).unwrap(),
                    weight,
                    "block weight at op index {}",
                    op_index
                ),
                Operation::AssertPayloadWeights {
                    block_root,
                    expected_full_weight,
                    expected_empty_weight,
                } => {
                    let block_index = fork_choice
                        .proto_array
                        .indices
                        .get(&block_root)
                        .unwrap_or_else(|| {
                            panic!(
                                "AssertPayloadWeights: block root not found at op index {}",
                                op_index
                            )
                        });
                    let node = fork_choice
                        .proto_array
                        .nodes
                        .get(*block_index)
                        .unwrap_or_else(|| {
                            panic!(
                                "AssertPayloadWeights: node not found at op index {}",
                                op_index
                            )
                        });
                    let v29 = node.as_v29().unwrap_or_else(|_| {
                        panic!(
                            "AssertPayloadWeights: node is not V29 at op index {}",
                            op_index
                        )
                    });
                    assert_eq!(
                        v29.full_payload_weight, expected_full_weight,
                        "full_payload_weight mismatch at op index {}",
                        op_index
                    );
                    assert_eq!(
                        v29.empty_payload_weight, expected_empty_weight,
                        "empty_payload_weight mismatch at op index {}",
                        op_index
                    );
                }
                Operation::AssertParentPayloadStatus {
                    block_root,
                    expected_status,
                } => {
                    let block_index = fork_choice
                        .proto_array
                        .indices
                        .get(&block_root)
                        .unwrap_or_else(|| {
                            panic!(
                                "AssertParentPayloadStatus: block root not found at op index {}",
                                op_index
                            )
                        });
                    let node = fork_choice
                        .proto_array
                        .nodes
                        .get(*block_index)
                        .unwrap_or_else(|| {
                            panic!(
                                "AssertParentPayloadStatus: node not found at op index {}",
                                op_index
                            )
                        });
                    let v29 = node.as_v29().unwrap_or_else(|_| {
                        panic!(
                            "AssertParentPayloadStatus: node is not V29 at op index {}",
                            op_index
                        )
                    });
                    assert_eq!(
                        v29.parent_payload_status, expected_status,
                        "parent_payload_status mismatch at op index {}",
                        op_index
                    );
                }
                Operation::SetPayloadTiebreak {
                    block_root,
                    is_timely,
                    is_data_available,
                } => {
                    let block_index = fork_choice
                        .proto_array
                        .indices
                        .get(&block_root)
                        .unwrap_or_else(|| {
                            panic!(
                                "SetPayloadTiebreak: block root not found at op index {}",
                                op_index
                            )
                        });
                    let node = fork_choice
                        .proto_array
                        .nodes
                        .get_mut(*block_index)
                        .unwrap_or_else(|| {
                            panic!(
                                "SetPayloadTiebreak: node not found at op index {}",
                                op_index
                            )
                        });
                    let node_v29 = node.as_v29_mut().unwrap_or_else(|_| {
                        panic!(
                            "SetPayloadTiebreak: node is not V29 at op index {}",
                            op_index
                        )
                    });
                    // Set all bits (exceeds any threshold) or clear all bits.
                    let fill = if is_timely { 0xFF } else { 0x00 };
                    node_v29.payload_timeliness_votes =
                        BitVector::from_bytes(smallvec::smallvec![fill; 64])
                            .expect("valid 512-bit bitvector");
                    let fill = if is_data_available { 0xFF } else { 0x00 };
                    node_v29.payload_data_availability_votes =
                        BitVector::from_bytes(smallvec::smallvec![fill; 64])
                            .expect("valid 512-bit bitvector");
                    // Mark all PTC members as having participated.
                    node_v29.ptc_participation =
                        BitVector::from_bytes(smallvec::smallvec![0xFF; 64])
                            .expect("valid 512-bit bitvector");
                    // Per spec, payload_timeliness/payload_data_availability require
                    // the payload to be in payload_states (payload_received).
                    node_v29.payload_received = is_timely || is_data_available;
                }
                Operation::ProcessExecutionPayloadEnvelope { block_root } => {
                    fork_choice
                        .on_valid_payload_envelope_received(block_root)
                        .unwrap_or_else(|e| {
                            panic!(
                                "on_execution_payload op at index {} returned error: {}",
                                op_index, e
                            )
                        });
                    check_bytes_round_trip(&fork_choice);
                }
                Operation::AssertPayloadReceived {
                    block_root,
                    expected,
                } => {
                    let actual = fork_choice.is_payload_received(&block_root);
                    assert_eq!(
                        actual, expected,
                        "payload_received mismatch at op index {}",
                        op_index
                    );
                }
                Operation::AssertPayloadStatusByWeight {
                    block_root,
                    expected_status,
                    current_slot,
                    proposer_boost_root,
                } => {
                    let actual = fork_choice
                        .get_canonical_payload_status::<MainnetEthSpec>(
                            &block_root,
                            current_slot.unwrap_or(last_current_slot),
                            proposer_boost_root.unwrap_or_else(Hash256::zero),
                            &spec,
                        )
                        .unwrap();
                    assert_eq!(
                        actual, expected_status,
                        "canonical payload status mismatch at op index {}",
                        op_index
                    );
                }
            }
        }
    }
}

/// Gives a root that is not the zero hash (unless i is `usize::MAX)`.
fn get_root(i: u64) -> Hash256 {
    Hash256::from_low_u64_be(i + 1)
}

/// Gives a hash that is not the zero hash (unless i is `usize::MAX)`.
fn get_hash(i: u64) -> ExecutionBlockHash {
    ExecutionBlockHash::from_root(get_root(i))
}

/// Gives a checkpoint with a root that is not the zero hash (unless i is `usize::MAX)`.
/// `Epoch` will always equal `i`.
fn get_checkpoint(i: u64) -> Checkpoint {
    Checkpoint {
        epoch: Epoch::new(i),
        root: get_root(i),
    }
}

/// Checks that `get_canonical_payload_status` agrees with the `payload_status`
/// returned by `find_head` for the head block.
fn assert_canonical_payload_status_matches_find_head(
    fork_choice: &ProtoArrayForkChoice,
    head: &Hash256,
    current_slot: Slot,
    proposer_boost_root: Hash256,
    spec: &ChainSpec,
    expected: PayloadStatus,
    op_index: usize,
) {
    match fork_choice.get_canonical_payload_status::<MainnetEthSpec>(
        head,
        current_slot,
        proposer_boost_root,
        spec,
    ) {
        Ok(actual) => assert_eq!(
            actual, expected,
            "get_canonical_payload_status disagreed with find_head for head {:?} at op index {}",
            head, op_index
        ),
        // Skip the check for pre-gloas nodes
        Err(Error::InvalidNodeVariant { .. }) => {}
        Err(e) => panic!(
            "get_canonical_payload_status failed at op index {}: {:?}",
            op_index, e
        ),
    }
}

fn check_bytes_round_trip(original: &ProtoArrayForkChoice) {
    let bytes = original.as_bytes();
    let decoded = ProtoArrayForkChoice::from_bytes(&bytes, original.balances.clone())
        .expect("fork choice should decode from bytes");
    assert!(
        *original == decoded,
        "fork choice should encode and decode without change"
    );
}
