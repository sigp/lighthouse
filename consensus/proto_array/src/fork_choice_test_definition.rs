mod ffg_updates;
mod no_votes;
mod votes;

use crate::proto_array_fork_choice::{Block, ProtoArrayForkChoice};
use serde_derive::{Deserialize, Serialize};
use types::{Epoch, Hash256, Slot};

pub use ffg_updates::*;
pub use no_votes::*;
pub use votes::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operation {
    FindHead {
        justified_epoch: Epoch,
        justified_root: Hash256,
        finalized_epoch: Epoch,
        justified_state_balances: Vec<u64>,
        expected_head: Hash256,
    },
    InvalidFindHead {
        justified_epoch: Epoch,
        justified_root: Hash256,
        finalized_epoch: Epoch,
        justified_state_balances: Vec<u64>,
    },
    ProcessBlock {
        slot: Slot,
        root: Hash256,
        parent_root: Hash256,
        justified_epoch: Epoch,
        finalized_epoch: Epoch,
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
    pub justified_epoch: Epoch,
    pub finalized_epoch: Epoch,
    pub finalized_root: Hash256,
    pub operations: Vec<Operation>,
}

impl ForkChoiceTestDefinition {
    pub fn run(self) {
        let mut fork_choice = ProtoArrayForkChoice::new(
            self.finalized_block_slot,
            Hash256::zero(),
            self.justified_epoch,
            self.finalized_epoch,
            self.finalized_root,
        )
        .expect("should create fork choice struct");

        for (op_index, op) in self.operations.into_iter().enumerate() {
            match op.clone() {
                Operation::FindHead {
                    justified_epoch,
                    justified_root,
                    finalized_epoch,
                    justified_state_balances,
                    expected_head,
                } => {
                    let head = fork_choice
                        .find_head(
                            justified_epoch,
                            justified_root,
                            finalized_epoch,
                            &justified_state_balances,
                        )
                        .expect(&format!(
                            "find_head op at index {} returned error",
                            op_index
                        ));

                    assert_eq!(
                        head, expected_head,
                        "Operation at index {} failed checks. Operation: {:?}",
                        op_index, op
                    );
                    check_bytes_round_trip(&fork_choice);
                }
                Operation::InvalidFindHead {
                    justified_epoch,
                    justified_root,
                    finalized_epoch,
                    justified_state_balances,
                } => {
                    let result = fork_choice.find_head(
                        justified_epoch,
                        justified_root,
                        finalized_epoch,
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
                    justified_epoch,
                    finalized_epoch,
                } => {
                    let block = Block {
                        slot,
                        root,
                        parent_root: Some(parent_root),
                        state_root: Hash256::zero(),
                        target_root: Hash256::zero(),
                        justified_epoch,
                        finalized_epoch,
                    };
                    fork_choice.process_block(block).expect(&format!(
                        "process_block op at index {} returned error",
                        op_index
                    ));
                    check_bytes_round_trip(&fork_choice);
                }
                Operation::ProcessAttestation {
                    validator_index,
                    block_root,
                    target_epoch,
                } => {
                    fork_choice
                        .process_attestation(validator_index, block_root, target_epoch)
                        .expect(&format!(
                            "process_attestation op at index {} returned error",
                            op_index
                        ));
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
    Hash256::from_low_u64_be(i)
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
