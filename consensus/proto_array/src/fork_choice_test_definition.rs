mod ffg_updates;
mod no_votes;
mod votes;

use crate::proto_array_fork_choice::{Block, ExecutionStatus, ProtoArrayForkChoice};
use serde_derive::{Deserialize, Serialize};
use types::{AttestationShufflingId, Checkpoint, Epoch, Hash256, Slot};

pub use ffg_updates::*;
pub use no_votes::*;
pub use votes::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operation {
    FindHead {
        justified_checkpoint: Checkpoint,
        finalized_checkpoint: Checkpoint,
        justified_state_balances: Vec<u64>,
        expected_head: Hash256,
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
    },
    ProcessAttestation {
        validator_index: usize,
        block_root: Hash256,
        target_epoch: Epoch,
    },
    Prune {
        finalized_root: Hash256,
        prune_threshold: usize,
        expected_len: usize,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkChoiceTestDefinition {
    pub finalized_block_slot: Slot,
    pub justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
    pub operations: Vec<Operation>,
}

impl ForkChoiceTestDefinition {
    pub fn run(self) {
        let junk_shuffling_id =
            AttestationShufflingId::from_components(Epoch::new(0), Hash256::zero());
        let execution_status = ExecutionStatus::irrelevant();
        let mut fork_choice = ProtoArrayForkChoice::new(
            self.finalized_block_slot,
            Hash256::zero(),
                self.justified_checkpoint,
            self.finalized_checkpoint,
            junk_shuffling_id.clone(),
            junk_shuffling_id,
            execution_status,
        )
        .expect("should create fork choice struct");

        for (op_index, op) in self.operations.into_iter().enumerate() {
            match op.clone() {
                Operation::FindHead {
                    justified_checkpoint,
                    finalized_checkpoint,
                    justified_state_balances,
                    expected_head,
                } => {
                    let head = fork_choice
                        .find_head(
                            justified_checkpoint,
                            finalized_checkpoint,
                            &justified_state_balances,
                        )
                        .map_err(|e| e)
                        .unwrap_or_else(|e| {
                            panic!("find_head op at index {} returned error {}", op_index, e)
                        });

                    assert_eq!(
                        head, expected_head,
                        "Operation at index {} failed checks. Operation: {:?}",
                        op_index, op
                    );
                    check_bytes_round_trip(&fork_choice);
                }
                Operation::InvalidFindHead {
                    justified_checkpoint,
                    finalized_checkpoint,
                    justified_state_balances,
                } => {
                    let result = fork_choice.find_head(
                        justified_checkpoint,
                        finalized_checkpoint,
                        &justified_state_balances,
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
                        execution_status,
                    };
                    fork_choice.process_block(block).unwrap_or_else(|e| {
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
                    target_epoch,
                } => {
                    fork_choice
                        .process_attestation(validator_index, block_root, target_epoch)
                        .unwrap_or_else(|_| {
                            panic!(
                                "process_attestation op at index {} returned error",
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
            }
        }
    }
}

/// Gives a hash that is not the zero hash (unless i is `usize::max_value)`.
fn get_hash(i: u64) -> Hash256 {
    Hash256::from_low_u64_be(i + 1)
}

/// Gives a checkpoint with a root that is not the zero hash (unless i is `usize::max_value)`.
/// `Epoch` will always equal `i + 1`.
fn get_checkpoint(i: u64) -> Checkpoint {
    Checkpoint {
        epoch: Epoch::new(i),
        root: get_hash(i ),
    }
}

fn check_bytes_round_trip(original: &ProtoArrayForkChoice) {
    let bytes = original.as_bytes();
    let decoded =
        ProtoArrayForkChoice::from_bytes(&bytes).expect("fork choice should decode from bytes");
    assert!(
        *original == decoded,
        "fork choice should encode and decode without change"
    );
}
