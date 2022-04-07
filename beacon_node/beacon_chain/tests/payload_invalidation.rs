#![cfg(not(debug_assertions))]

use beacon_chain::{
    test_utils::{BeaconChainHarness, EphemeralHarnessType},
    BeaconChainError, BlockError, ExecutionPayloadError, HeadInfo, StateSkipConfig,
    WhenSlotSkipped, INVALID_JUSTIFIED_PAYLOAD_SHUTDOWN_REASON,
};
use execution_layer::{
    json_structures::{JsonForkChoiceStateV1, JsonPayloadAttributesV1},
    ExecutionLayer, ForkChoiceState, PayloadAttributes,
};
use fork_choice::{Error as ForkChoiceError, InvalidationOperation, PayloadVerificationStatus};
use proto_array::{Error as ProtoArrayError, ExecutionStatus};
use slot_clock::SlotClock;
use std::time::Duration;
use task_executor::ShutdownReason;
use types::*;

const VALIDATOR_COUNT: usize = 32;

type E = MainnetEthSpec;

#[derive(PartialEq, Clone)]
enum Payload {
    Valid,
    Invalid {
        latest_valid_hash: Option<ExecutionBlockHash>,
    },
    Syncing,
}

struct InvalidPayloadRig {
    harness: BeaconChainHarness<EphemeralHarnessType<E>>,
    enable_attestations: bool,
}

impl InvalidPayloadRig {
    fn new() -> Self {
        let mut spec = E::default_spec();
        spec.altair_fork_epoch = Some(Epoch::new(0));
        spec.bellatrix_fork_epoch = Some(Epoch::new(0));

        let harness = BeaconChainHarness::builder(MainnetEthSpec)
            .spec(spec)
            .deterministic_keypairs(VALIDATOR_COUNT)
            .mock_execution_layer()
            .fresh_ephemeral_store()
            .build();

        // Move to slot 1.
        harness.advance_slot();

        Self {
            harness,
            enable_attestations: false,
        }
    }

    fn enable_attestations(mut self) -> Self {
        self.enable_attestations = true;
        self
    }

    fn execution_layer(&self) -> ExecutionLayer {
        self.harness.chain.execution_layer.clone().unwrap()
    }

    fn block_hash(&self, block_root: Hash256) -> ExecutionBlockHash {
        self.harness
            .chain
            .get_block(&block_root)
            .unwrap()
            .unwrap()
            .message()
            .body()
            .execution_payload()
            .unwrap()
            .block_hash()
    }

    fn execution_status(&self, block_root: Hash256) -> ExecutionStatus {
        self.harness
            .chain
            .fork_choice
            .read()
            .get_block(&block_root)
            .unwrap()
            .execution_status
    }

    fn fork_choice(&self) {
        self.harness.chain.fork_choice().unwrap();
    }

    fn head_info(&self) -> HeadInfo {
        self.harness.chain.head_info().unwrap()
    }

    fn previous_forkchoice_update_params(&self) -> (ForkChoiceState, PayloadAttributes) {
        let mock_execution_layer = self.harness.mock_execution_layer.as_ref().unwrap();
        let json = mock_execution_layer
            .server
            .take_previous_request()
            .expect("no previous request");
        let params = json.get("params").expect("no params");

        let fork_choice_state_json = params.get(0).expect("no payload param");
        let fork_choice_state: JsonForkChoiceStateV1 =
            serde_json::from_value(fork_choice_state_json.clone()).unwrap();

        let payload_param_json = params.get(1).expect("no payload param");
        let attributes: JsonPayloadAttributesV1 =
            serde_json::from_value(payload_param_json.clone()).unwrap();

        (fork_choice_state.into(), attributes.into())
    }

    fn previous_payload_attributes(&self) -> PayloadAttributes {
        let (_, payload_attributes) = self.previous_forkchoice_update_params();
        payload_attributes
    }

    fn move_to_terminal_block(&self) {
        let mock_execution_layer = self.harness.mock_execution_layer.as_ref().unwrap();
        mock_execution_layer
            .server
            .execution_block_generator()
            .move_to_terminal_block()
            .unwrap();
    }

    fn latest_execution_block_hash(&self) -> ExecutionBlockHash {
        let mock_execution_layer = self.harness.mock_execution_layer.as_ref().unwrap();
        mock_execution_layer
            .server
            .execution_block_generator()
            .latest_execution_block()
            .unwrap()
            .block_hash
    }

    fn build_blocks(&mut self, num_blocks: u64, is_valid: Payload) -> Vec<Hash256> {
        (0..num_blocks)
            .map(|_| self.import_block(is_valid.clone()))
            .collect()
    }

    fn move_to_first_justification(&mut self, is_valid: Payload) {
        let slots_till_justification = E::slots_per_epoch() * 3;
        self.build_blocks(slots_till_justification, is_valid);

        let justified_checkpoint = self.head_info().current_justified_checkpoint;
        assert_eq!(justified_checkpoint.epoch, 2);
    }

    fn import_block(&mut self, is_valid: Payload) -> Hash256 {
        self.import_block_parametric(is_valid, |error| {
            matches!(
                error,
                BlockError::ExecutionPayloadError(
                    ExecutionPayloadError::RejectedByExecutionEngine { .. }
                )
            )
        })
    }

    fn block_root_at_slot(&self, slot: Slot) -> Option<Hash256> {
        self.harness
            .chain
            .block_root_at_slot(slot, WhenSlotSkipped::None)
            .unwrap()
    }

    fn validate_manually(&self, block_root: Hash256) {
        self.harness
            .chain
            .fork_choice
            .write()
            .on_valid_execution_payload(block_root)
            .unwrap();
    }

    fn import_block_parametric<F: Fn(&BlockError<E>) -> bool>(
        &mut self,
        is_valid: Payload,
        evaluate_error: F,
    ) -> Hash256 {
        let mock_execution_layer = self.harness.mock_execution_layer.as_ref().unwrap();

        let head = self.harness.chain.head().unwrap();
        let state = head.beacon_state;
        let slot = state.slot() + 1;
        let (block, post_state) = self.harness.make_block(state, slot);
        let block_root = block.canonical_root();

        match is_valid {
            Payload::Valid | Payload::Syncing => {
                if is_valid == Payload::Syncing {
                    // Importing a payload whilst returning `SYNCING` simulates an EE that obtains
                    // the block via it's own means (e.g., devp2p).
                    let should_import_payload = true;
                    mock_execution_layer
                        .server
                        .all_payloads_syncing(should_import_payload);
                } else {
                    mock_execution_layer.server.full_payload_verification();
                }
                let root = self.harness.process_block(slot, block.clone()).unwrap();

                if self.enable_attestations {
                    let all_validators: Vec<usize> = (0..VALIDATOR_COUNT).collect();
                    self.harness.attest_block(
                        &post_state,
                        block.state_root(),
                        block_root.into(),
                        &block,
                        &all_validators,
                    );
                }

                let execution_status = self.execution_status(root.into());

                match is_valid {
                    Payload::Syncing => assert!(execution_status.is_not_verified()),
                    Payload::Valid => assert!(execution_status.is_valid()),
                    Payload::Invalid { .. } => unreachable!(),
                }

                assert_eq!(
                    self.harness.chain.get_block(&block_root).unwrap().unwrap(),
                    block,
                    "block from db must match block imported"
                );
            }
            Payload::Invalid { latest_valid_hash } => {
                let latest_valid_hash = latest_valid_hash
                    .unwrap_or_else(|| self.block_hash(block.message().parent_root()));

                mock_execution_layer
                    .server
                    .all_payloads_invalid(latest_valid_hash);

                match self.harness.process_block(slot, block) {
                    Err(error) if evaluate_error(&error) => (),
                    Err(other) => {
                        panic!("evaluate_error returned false with {:?}", other)
                    }
                    Ok(_) => panic!("block with invalid payload was imported"),
                };

                assert!(
                    self.harness
                        .chain
                        .fork_choice
                        .read()
                        .get_block(&block_root)
                        .is_none(),
                    "invalid block must not exist in fork choice"
                );
                assert!(
                    self.harness.chain.get_block(&block_root).unwrap().is_none(),
                    "invalid block cannot be accessed via get_block"
                );
            }
        }

        block_root
    }

    fn invalidate_manually(&self, block_root: Hash256) {
        self.harness
            .chain
            .process_invalid_execution_payload(&InvalidationOperation::InvalidateOne { block_root })
            .unwrap();
    }
}

/// Simple test of the different import types.
#[test]
fn valid_invalid_syncing() {
    let mut rig = InvalidPayloadRig::new();
    rig.move_to_terminal_block();

    rig.import_block(Payload::Valid);
    rig.import_block(Payload::Invalid {
        latest_valid_hash: None,
    });
    rig.import_block(Payload::Syncing);
}

/// Ensure that an invalid payload can invalidate its parent too (given the right
/// `latest_valid_hash`.
#[test]
fn invalid_payload_invalidates_parent() {
    let mut rig = InvalidPayloadRig::new().enable_attestations();
    rig.move_to_terminal_block();
    rig.import_block(Payload::Valid); // Import a valid transition block.
    rig.move_to_first_justification(Payload::Syncing);

    let roots = vec![
        rig.import_block(Payload::Syncing),
        rig.import_block(Payload::Syncing),
        rig.import_block(Payload::Syncing),
    ];

    let latest_valid_hash = rig.block_hash(roots[0]);

    rig.import_block(Payload::Invalid {
        latest_valid_hash: Some(latest_valid_hash),
    });

    assert!(rig.execution_status(roots[0]).is_valid());
    assert!(rig.execution_status(roots[1]).is_invalid());
    assert!(rig.execution_status(roots[2]).is_invalid());

    assert_eq!(rig.head_info().block_root, roots[0]);
}

/// Ensure the client tries to exit when the justified checkpoint is invalidated.
#[test]
fn justified_checkpoint_becomes_invalid() {
    let mut rig = InvalidPayloadRig::new().enable_attestations();
    rig.move_to_terminal_block();
    rig.import_block(Payload::Valid); // Import a valid transition block.
    rig.move_to_first_justification(Payload::Syncing);

    let justified_checkpoint = rig.head_info().current_justified_checkpoint;
    let parent_root_of_justified = rig
        .harness
        .chain
        .get_block(&justified_checkpoint.root)
        .unwrap()
        .unwrap()
        .parent_root();
    let parent_hash_of_justified = rig.block_hash(parent_root_of_justified);

    // No service should have triggered a shutdown, yet.
    assert!(rig.harness.shutdown_reasons().is_empty());

    // Import a block that will invalidate the justified checkpoint.
    rig.import_block_parametric(
        Payload::Invalid {
            latest_valid_hash: Some(parent_hash_of_justified),
        },
        |error| {
            matches!(
                error,
                // The block import should fail since the beacon chain knows the justified payload
                // is invalid.
                BlockError::BeaconChainError(BeaconChainError::JustifiedPayloadInvalid { .. })
            )
        },
    );

    // The beacon chain should have triggered a shutdown.
    assert_eq!(
        rig.harness.shutdown_reasons(),
        vec![ShutdownReason::Failure(
            INVALID_JUSTIFIED_PAYLOAD_SHUTDOWN_REASON
        )]
    );
}

/// Ensure that a `latest_valid_hash` for a pre-finality block only reverts a single block.
#[test]
fn pre_finalized_latest_valid_hash() {
    let num_blocks = E::slots_per_epoch() * 4;
    let finalized_epoch = 2;

    let mut rig = InvalidPayloadRig::new().enable_attestations();
    rig.move_to_terminal_block();
    let mut blocks = vec![];
    blocks.push(rig.import_block(Payload::Valid)); // Import a valid transition block.
    blocks.extend(rig.build_blocks(num_blocks - 1, Payload::Syncing));

    assert_eq!(rig.head_info().finalized_checkpoint.epoch, finalized_epoch);

    let pre_finalized_block_root = rig.block_root_at_slot(Slot::new(1)).unwrap();
    let pre_finalized_block_hash = rig.block_hash(pre_finalized_block_root);

    // No service should have triggered a shutdown, yet.
    assert!(rig.harness.shutdown_reasons().is_empty());

    // Import a pre-finalized block.
    rig.import_block(Payload::Invalid {
        latest_valid_hash: Some(pre_finalized_block_hash),
    });

    // The latest imported block should be the head.
    assert_eq!(rig.head_info().block_root, *blocks.last().unwrap());

    // The beacon chain should *not* have triggered a shutdown.
    assert_eq!(rig.harness.shutdown_reasons(), vec![]);

    // All blocks should still be unverified.
    for i in E::slots_per_epoch() * finalized_epoch..num_blocks {
        let slot = Slot::new(i);
        let root = rig.block_root_at_slot(slot).unwrap();
        if slot == 1 {
            assert!(rig.execution_status(root).is_valid());
        } else {
            assert!(rig.execution_status(root).is_not_verified());
        }
    }
}

/// Ensure that a `latest_valid_hash` will:
///
/// - Invalidate descendants of `latest_valid_root`.
/// - Validate `latest_valid_root` and its ancestors.
#[test]
fn latest_valid_hash_will_validate() {
    const LATEST_VALID_SLOT: u64 = 3;

    let mut rig = InvalidPayloadRig::new().enable_attestations();
    rig.move_to_terminal_block();

    let mut blocks = vec![];
    blocks.push(rig.import_block(Payload::Valid)); // Import a valid transition block.
    blocks.extend(rig.build_blocks(4, Payload::Syncing));

    let latest_valid_root = rig
        .block_root_at_slot(Slot::new(LATEST_VALID_SLOT))
        .unwrap();
    let latest_valid_hash = rig.block_hash(latest_valid_root);

    rig.import_block(Payload::Invalid {
        latest_valid_hash: Some(latest_valid_hash),
    });

    assert_eq!(rig.head_info().slot, LATEST_VALID_SLOT);

    for slot in 0..=5 {
        let slot = Slot::new(slot);
        let root = if slot > 0 {
            // If not the genesis slot, check the blocks we just produced.
            blocks[slot.as_usize() - 1]
        } else {
            // Genesis slot
            rig.block_root_at_slot(slot).unwrap()
        };
        let execution_status = rig.execution_status(root);

        if slot > LATEST_VALID_SLOT {
            assert!(execution_status.is_invalid())
        } else if slot == 0 {
            assert!(execution_status.is_irrelevant())
        } else {
            assert!(execution_status.is_valid())
        }
    }
}

/// Check behaviour when the `latest_valid_hash` is a junk value.
#[test]
fn latest_valid_hash_is_junk() {
    let num_blocks = E::slots_per_epoch() * 5;
    let finalized_epoch = 3;

    let mut rig = InvalidPayloadRig::new().enable_attestations();
    rig.move_to_terminal_block();
    let mut blocks = vec![];
    blocks.push(rig.import_block(Payload::Valid)); // Import a valid transition block.
    blocks.extend(rig.build_blocks(num_blocks, Payload::Syncing));

    assert_eq!(rig.head_info().finalized_checkpoint.epoch, finalized_epoch);

    // No service should have triggered a shutdown, yet.
    assert!(rig.harness.shutdown_reasons().is_empty());

    let junk_hash = ExecutionBlockHash::repeat_byte(42);
    rig.import_block(Payload::Invalid {
        latest_valid_hash: Some(junk_hash),
    });

    // The latest imported block should be the head.
    assert_eq!(rig.head_info().block_root, *blocks.last().unwrap());

    // The beacon chain should *not* have triggered a shutdown.
    assert_eq!(rig.harness.shutdown_reasons(), vec![]);

    // All blocks should still be unverified.
    for i in E::slots_per_epoch() * finalized_epoch..num_blocks {
        let slot = Slot::new(i);
        let root = rig.block_root_at_slot(slot).unwrap();
        if slot == 1 {
            assert!(rig.execution_status(root).is_valid());
        } else {
            assert!(rig.execution_status(root).is_not_verified());
        }
    }
}

/// Check that descendants of invalid blocks are also invalidated.
#[test]
fn invalidates_all_descendants() {
    let num_blocks = E::slots_per_epoch() * 4 + E::slots_per_epoch() / 2;
    let finalized_epoch = 2;
    let finalized_slot = E::slots_per_epoch() * 2;

    let mut rig = InvalidPayloadRig::new().enable_attestations();
    rig.move_to_terminal_block();
    rig.import_block(Payload::Valid); // Import a valid transition block.
    let blocks = rig.build_blocks(num_blocks, Payload::Syncing);

    assert_eq!(rig.head_info().finalized_checkpoint.epoch, finalized_epoch);
    assert_eq!(rig.head_info().block_root, *blocks.last().unwrap());

    // Apply a block which conflicts with the canonical chain.
    let fork_slot = Slot::new(4 * E::slots_per_epoch() + 3);
    let fork_parent_slot = fork_slot - 1;
    let fork_parent_state = rig
        .harness
        .chain
        .state_at_slot(fork_parent_slot, StateSkipConfig::WithStateRoots)
        .unwrap();
    assert_eq!(fork_parent_state.slot(), fork_parent_slot);
    let (fork_block, _fork_post_state) = rig.harness.make_block(fork_parent_state, fork_slot);
    let fork_block_root = rig.harness.chain.process_block(fork_block).unwrap();
    rig.fork_choice();

    // The latest valid hash will be set to the grandparent of the fork block. This means that the
    // parent of the fork block will become invalid.
    let latest_valid_slot = fork_parent_slot - 1;
    let latest_valid_root = rig
        .harness
        .chain
        .block_root_at_slot(latest_valid_slot, WhenSlotSkipped::None)
        .unwrap()
        .unwrap();
    assert!(blocks.contains(&latest_valid_root));
    let latest_valid_hash = rig.block_hash(latest_valid_root);

    // The new block should not become the head, the old head should remain.
    assert_eq!(rig.head_info().block_root, *blocks.last().unwrap());

    rig.import_block(Payload::Invalid {
        latest_valid_hash: Some(latest_valid_hash),
    });

    // The block before the fork should become the head.
    assert_eq!(rig.head_info().block_root, latest_valid_root);

    // The fork block should be invalidated, even though it's not an ancestor of the block that
    // triggered the INVALID response from the EL.
    assert!(rig.execution_status(fork_block_root).is_invalid());

    for root in blocks {
        let slot = rig.harness.chain.get_block(&root).unwrap().unwrap().slot();

        // Fork choice doesn't have info about pre-finalization, nothing to check here.
        if slot < finalized_slot {
            continue;
        }

        let execution_status = rig.execution_status(root);
        if slot <= latest_valid_slot {
            // Blocks prior to the latest valid hash are valid.
            assert!(execution_status.is_valid());
        } else {
            // Blocks after the latest valid hash are invalid.
            assert!(execution_status.is_invalid());
        }
    }
}

/// Check that the head will switch after the canonical branch is invalidated.
#[test]
fn switches_heads() {
    let num_blocks = E::slots_per_epoch() * 4 + E::slots_per_epoch() / 2;
    let finalized_epoch = 2;
    let finalized_slot = E::slots_per_epoch() * 2;

    let mut rig = InvalidPayloadRig::new().enable_attestations();
    rig.move_to_terminal_block();
    rig.import_block(Payload::Valid); // Import a valid transition block.
    let blocks = rig.build_blocks(num_blocks, Payload::Syncing);

    assert_eq!(rig.head_info().finalized_checkpoint.epoch, finalized_epoch);
    assert_eq!(rig.head_info().block_root, *blocks.last().unwrap());

    // Apply a block which conflicts with the canonical chain.
    let fork_slot = Slot::new(4 * E::slots_per_epoch() + 3);
    let fork_parent_slot = fork_slot - 1;
    let fork_parent_state = rig
        .harness
        .chain
        .state_at_slot(fork_parent_slot, StateSkipConfig::WithStateRoots)
        .unwrap();
    assert_eq!(fork_parent_state.slot(), fork_parent_slot);
    let (fork_block, _fork_post_state) = rig.harness.make_block(fork_parent_state, fork_slot);
    let fork_parent_root = fork_block.parent_root();
    let fork_block_root = rig.harness.chain.process_block(fork_block).unwrap();
    rig.fork_choice();

    let latest_valid_slot = fork_parent_slot;
    let latest_valid_hash = rig.block_hash(fork_parent_root);

    // The new block should not become the head, the old head should remain.
    assert_eq!(rig.head_info().block_root, *blocks.last().unwrap());

    rig.import_block(Payload::Invalid {
        latest_valid_hash: Some(latest_valid_hash),
    });

    // The fork block should become the head.
    assert_eq!(rig.head_info().block_root, fork_block_root);

    // The fork block has not yet been validated.
    assert!(rig.execution_status(fork_block_root).is_not_verified());

    for root in blocks {
        let slot = rig.harness.chain.get_block(&root).unwrap().unwrap().slot();

        // Fork choice doesn't have info about pre-finalization, nothing to check here.
        if slot < finalized_slot {
            continue;
        }

        let execution_status = rig.execution_status(root);
        if slot <= latest_valid_slot {
            // Blocks prior to the latest valid hash are valid.
            assert!(execution_status.is_valid());
        } else {
            // Blocks after the latest valid hash are invalid.
            assert!(execution_status.is_invalid());
        }
    }
}

#[test]
fn invalid_during_processing() {
    let mut rig = InvalidPayloadRig::new();
    rig.move_to_terminal_block();

    let roots = &[
        rig.import_block(Payload::Valid),
        rig.import_block(Payload::Invalid {
            latest_valid_hash: None,
        }),
        rig.import_block(Payload::Valid),
    ];

    // 0 should be present in the chain.
    assert!(rig.harness.chain.get_block(&roots[0]).unwrap().is_some());
    // 1 should *not* be present in the chain.
    assert_eq!(rig.harness.chain.get_block(&roots[1]).unwrap(), None);
    // 2 should be the head.
    let head = rig.harness.chain.head_info().unwrap();
    assert_eq!(head.block_root, roots[2]);
}

#[test]
fn invalid_after_optimistic_sync() {
    let mut rig = InvalidPayloadRig::new().enable_attestations();
    rig.move_to_terminal_block();
    rig.import_block(Payload::Valid); // Import a valid transition block.

    let mut roots = vec![
        rig.import_block(Payload::Syncing),
        rig.import_block(Payload::Syncing),
        rig.import_block(Payload::Syncing),
    ];

    for root in &roots {
        assert!(rig.harness.chain.get_block(root).unwrap().is_some());
    }

    // 2 should be the head.
    let head = rig.harness.chain.head_info().unwrap();
    assert_eq!(head.block_root, roots[2]);

    roots.push(rig.import_block(Payload::Invalid {
        latest_valid_hash: Some(rig.block_hash(roots[1])),
    }));

    // Running fork choice is necessary since a block has been invalidated.
    rig.fork_choice();

    // 1 should be the head, since 2 was invalidated.
    let head = rig.harness.chain.head_info().unwrap();
    assert_eq!(head.block_root, roots[1]);
}

#[test]
fn manually_validate_child() {
    let mut rig = InvalidPayloadRig::new().enable_attestations();
    rig.move_to_terminal_block();
    rig.import_block(Payload::Valid); // Import a valid transition block.

    let parent = rig.import_block(Payload::Syncing);
    let child = rig.import_block(Payload::Syncing);

    assert!(rig.execution_status(parent).is_not_verified());
    assert!(rig.execution_status(child).is_not_verified());

    rig.validate_manually(child);

    assert!(rig.execution_status(parent).is_valid());
    assert!(rig.execution_status(child).is_valid());
}

#[test]
fn manually_validate_parent() {
    let mut rig = InvalidPayloadRig::new().enable_attestations();
    rig.move_to_terminal_block();
    rig.import_block(Payload::Valid); // Import a valid transition block.

    let parent = rig.import_block(Payload::Syncing);
    let child = rig.import_block(Payload::Syncing);

    assert!(rig.execution_status(parent).is_not_verified());
    assert!(rig.execution_status(child).is_not_verified());

    rig.validate_manually(parent);

    assert!(rig.execution_status(parent).is_valid());
    assert!(rig.execution_status(child).is_not_verified());
}

#[test]
fn payload_preparation() {
    let mut rig = InvalidPayloadRig::new();
    rig.move_to_terminal_block();
    rig.import_block(Payload::Valid);

    let el = rig.execution_layer();
    let head = rig.harness.chain.head().unwrap();
    let current_slot = rig.harness.chain.slot().unwrap();
    assert_eq!(head.beacon_state.slot(), 1);
    assert_eq!(current_slot, 1);

    let next_slot = current_slot + 1;
    let proposer = head
        .beacon_state
        .get_beacon_proposer_index(next_slot, &rig.harness.chain.spec)
        .unwrap();

    let fee_recipient = Address::repeat_byte(99);

    // Provide preparation data to the EL for `proposer`.
    el.update_proposer_preparation_blocking(
        Epoch::new(1),
        &[ProposerPreparationData {
            validator_index: proposer as u64,
            fee_recipient,
        }],
    )
    .unwrap();

    rig.harness
        .chain
        .prepare_beacon_proposer_blocking()
        .unwrap();

    let payload_attributes = PayloadAttributes {
        timestamp: rig
            .harness
            .chain
            .slot_clock
            .start_of(next_slot)
            .unwrap()
            .as_secs(),
        prev_randao: *head
            .beacon_state
            .get_randao_mix(head.beacon_state.current_epoch())
            .unwrap(),
        suggested_fee_recipient: fee_recipient,
    };
    assert_eq!(rig.previous_payload_attributes(), payload_attributes);
}

#[test]
fn invalid_parent() {
    let mut rig = InvalidPayloadRig::new();
    rig.move_to_terminal_block();
    rig.import_block(Payload::Valid); // Import a valid transition block.

    // Import a syncing block atop the transition block (we'll call this the "parent block" since we
    // build another block on it later).
    let parent_root = rig.import_block(Payload::Syncing);
    let parent_block = rig.harness.get_block(parent_root.into()).unwrap();
    let parent_state = rig
        .harness
        .get_hot_state(parent_block.state_root().into())
        .unwrap();

    // Produce another block atop the parent, but don't import yet.
    let slot = parent_block.slot() + 1;
    rig.harness.set_current_slot(slot);
    let (block, state) = rig.harness.make_block(parent_state, slot);
    let block_root = block.canonical_root();
    assert_eq!(block.parent_root(), parent_root);

    // Invalidate the parent block.
    rig.invalidate_manually(parent_root);
    assert!(rig.execution_status(parent_root).is_invalid());

    // Ensure the block built atop an invalid payload is invalid for gossip.
    assert!(matches!(
        rig.harness.chain.verify_block_for_gossip(block.clone()),
        Err(BlockError::ParentExecutionPayloadInvalid { parent_root: invalid_root })
        if invalid_root == parent_root
    ));

    // Ensure the block built atop an invalid payload is invalid for import.
    assert!(matches!(
        rig.harness.chain.process_block(block.clone()),
        Err(BlockError::ParentExecutionPayloadInvalid { parent_root: invalid_root })
        if invalid_root == parent_root
    ));

    // Ensure the block built atop an invalid payload cannot be imported to fork choice.
    let (block, _block_signature) = block.deconstruct();
    assert!(matches!(
        rig.harness.chain.fork_choice.write().on_block(
            slot,
            &block,
            block_root,
            Duration::from_secs(0),
            &state,
            PayloadVerificationStatus::NotVerified,
            &rig.harness.chain.spec
        ),
        Err(ForkChoiceError::ProtoArrayError(message))
        if message.contains(&format!(
            "{:?}",
            ProtoArrayError::ParentExecutionStatusIsInvalid {
                block_root,
                parent_root
            }
        ))
    ));
}

/// Tests to ensure that we will still send a proposer preparation
#[test]
fn payload_preparation_before_transition_block() {
    let rig = InvalidPayloadRig::new();
    let el = rig.execution_layer();

    let head = rig.harness.chain.head().unwrap();
    let head_info = rig.head_info();
    assert!(
        !head_info.is_merge_transition_complete,
        "the head block is pre-transition"
    );
    assert_eq!(
        head_info.execution_payload_block_hash,
        Some(ExecutionBlockHash::zero()),
        "the head block is post-bellatrix"
    );

    let current_slot = rig.harness.chain.slot().unwrap();
    let next_slot = current_slot + 1;
    let proposer = head
        .beacon_state
        .get_beacon_proposer_index(next_slot, &rig.harness.chain.spec)
        .unwrap();
    let fee_recipient = Address::repeat_byte(99);

    // Provide preparation data to the EL for `proposer`.
    el.update_proposer_preparation_blocking(
        Epoch::new(0),
        &[ProposerPreparationData {
            validator_index: proposer as u64,
            fee_recipient,
        }],
    )
    .unwrap();

    rig.move_to_terminal_block();

    rig.harness
        .chain
        .prepare_beacon_proposer_blocking()
        .unwrap();
    rig.harness
        .chain
        .update_execution_engine_forkchoice_blocking(current_slot)
        .unwrap();

    let (fork_choice_state, payload_attributes) = rig.previous_forkchoice_update_params();
    let latest_block_hash = rig.latest_execution_block_hash();
    assert_eq!(payload_attributes.suggested_fee_recipient, fee_recipient);
    assert_eq!(fork_choice_state.head_block_hash, latest_block_hash);
}
