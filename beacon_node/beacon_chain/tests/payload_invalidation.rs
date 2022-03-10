#![cfg(not(debug_assertions))]

use beacon_chain::{
    test_utils::{BeaconChainHarness, EphemeralHarnessType},
    BeaconChainError, BlockError, ExecutionPayloadError, StateSkipConfig, WhenSlotSkipped,
    INVALID_JUSTIFIED_PAYLOAD_SHUTDOWN_REASON,
};
use execution_layer::{
    json_structures::{JsonForkChoiceStateV1, JsonPayloadAttributesV1},
    ExecutionLayer, ForkChoiceState, PayloadAttributes,
};
use fork_choice::{Error as ForkChoiceError, InvalidationOperation, PayloadVerificationStatus};
use proto_array::{Error as ProtoArrayError, ExecutionStatus};
use slot_clock::SlotClock;
use std::sync::Arc;
use std::time::Duration;
use task_executor::ShutdownReason;
use tree_hash::TreeHash;
use types::*;

const VALIDATOR_COUNT: usize = 32;

type E = MainnetEthSpec;

#[derive(PartialEq, Clone, Copy)]
enum Payload {
    Valid,
    Invalid {
        latest_valid_hash: Option<ExecutionBlockHash>,
    },
    Syncing,
    InvalidBlockHash,
    InvalidTerminalBlock,
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

    fn execution_layer(&self) -> ExecutionLayer<E> {
        self.harness.chain.execution_layer.clone().unwrap()
    }

    fn block_hash(&self, block_root: Hash256) -> ExecutionBlockHash {
        self.harness
            .chain
            .get_blinded_block(&block_root)
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
            .canonical_head
            .fork_choice_read_lock()
            .get_block(&block_root)
            .unwrap()
            .execution_status
    }

    async fn recompute_head(&self) {
        self.harness
            .chain
            .recompute_head_at_current_slot()
            .await
            .unwrap();
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

    async fn build_blocks(&mut self, num_blocks: u64, is_valid: Payload) -> Vec<Hash256> {
        let mut roots = Vec::with_capacity(num_blocks as usize);
        for _ in 0..num_blocks {
            roots.push(self.import_block(is_valid.clone()).await);
        }
        roots
    }

    async fn move_to_first_justification(&mut self, is_valid: Payload) {
        let slots_till_justification = E::slots_per_epoch() * 3;
        self.build_blocks(slots_till_justification, is_valid).await;

        let justified_checkpoint = self.harness.justified_checkpoint();
        assert_eq!(justified_checkpoint.epoch, 2);
    }

    /// Import a block while setting the newPayload and forkchoiceUpdated responses to `is_valid`.
    async fn import_block(&mut self, is_valid: Payload) -> Hash256 {
        self.import_block_parametric(is_valid, is_valid, |error| {
            matches!(
                error,
                BlockError::ExecutionPayloadError(
                    ExecutionPayloadError::RejectedByExecutionEngine { .. }
                )
            )
        })
        .await
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
            .canonical_head
            .fork_choice_write_lock()
            .on_valid_execution_payload(block_root)
            .unwrap();
    }

    async fn import_block_parametric<F: Fn(&BlockError<E>) -> bool>(
        &mut self,
        new_payload_response: Payload,
        forkchoice_response: Payload,
        evaluate_error: F,
    ) -> Hash256 {
        let mock_execution_layer = self.harness.mock_execution_layer.as_ref().unwrap();

        let head = self.harness.chain.head_snapshot();
        let state = head.beacon_state.clone_with_only_committee_caches();
        let slot = state.slot() + 1;
        let (block, post_state) = self.harness.make_block(state, slot).await;
        let block_root = block.canonical_root();

        let set_new_payload = |payload: Payload| match payload {
            Payload::Valid => mock_execution_layer
                .server
                .all_payloads_valid_on_new_payload(),
            Payload::Syncing => mock_execution_layer
                .server
                .all_payloads_syncing_on_new_payload(true),
            Payload::Invalid { latest_valid_hash } => {
                let latest_valid_hash = latest_valid_hash
                    .unwrap_or_else(|| self.block_hash(block.message().parent_root()));
                mock_execution_layer
                    .server
                    .all_payloads_invalid_on_new_payload(latest_valid_hash)
            }
            Payload::InvalidBlockHash => mock_execution_layer
                .server
                .all_payloads_invalid_block_hash_on_new_payload(),
            Payload::InvalidTerminalBlock => mock_execution_layer
                .server
                .all_payloads_invalid_terminal_block_on_new_payload(),
        };
        let set_forkchoice_updated = |payload: Payload| match payload {
            Payload::Valid => mock_execution_layer
                .server
                .all_payloads_valid_on_forkchoice_updated(),
            Payload::Syncing => mock_execution_layer
                .server
                .all_payloads_syncing_on_forkchoice_updated(),
            Payload::Invalid { latest_valid_hash } => {
                let latest_valid_hash = latest_valid_hash
                    .unwrap_or_else(|| self.block_hash(block.message().parent_root()));
                mock_execution_layer
                    .server
                    .all_payloads_invalid_on_forkchoice_updated(latest_valid_hash)
            }
            Payload::InvalidBlockHash => mock_execution_layer
                .server
                .all_payloads_invalid_block_hash_on_forkchoice_updated(),
            Payload::InvalidTerminalBlock => mock_execution_layer
                .server
                .all_payloads_invalid_terminal_block_on_forkchoice_updated(),
        };

        match (new_payload_response, forkchoice_response) {
            (Payload::Valid | Payload::Syncing, Payload::Valid | Payload::Syncing) => {
                if new_payload_response == Payload::Syncing {
                    set_new_payload(new_payload_response);
                    set_forkchoice_updated(forkchoice_response);
                } else {
                    mock_execution_layer.server.full_payload_verification();
                }
                let root = self
                    .harness
                    .process_block(slot, block.clone())
                    .await
                    .unwrap();

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

                match forkchoice_response {
                    Payload::Syncing => assert!(execution_status.is_optimistic()),
                    Payload::Valid => assert!(execution_status.is_valid_and_post_bellatrix()),
                    Payload::Invalid { .. }
                    | Payload::InvalidBlockHash
                    | Payload::InvalidTerminalBlock => unreachable!(),
                }

                assert_eq!(
                    self.harness
                        .chain
                        .store
                        .get_full_block(&block_root)
                        .unwrap()
                        .unwrap(),
                    block,
                    "block from db must match block imported"
                );
            }
            (
                Payload::Invalid { .. } | Payload::InvalidBlockHash | Payload::InvalidTerminalBlock,
                _,
            )
            | (
                _,
                Payload::Invalid { .. } | Payload::InvalidBlockHash | Payload::InvalidTerminalBlock,
            ) => {
                set_new_payload(new_payload_response);
                set_forkchoice_updated(forkchoice_response);

                match self.harness.process_block(slot, block).await {
                    Err(error) if evaluate_error(&error) => (),
                    Err(other) => {
                        panic!("evaluate_error returned false with {:?}", other)
                    }
                    Ok(_) => {
                        // An invalid payload should only be imported initially if its status when
                        // initially supplied to the EE is Valid or Syncing.
                        assert!(matches!(
                            new_payload_response,
                            Payload::Valid | Payload::Syncing
                        ));
                    }
                };

                let block_in_forkchoice = self
                    .harness
                    .chain
                    .canonical_head
                    .fork_choice_read_lock()
                    .get_block(&block_root);
                if let Payload::Invalid { .. } = new_payload_response {
                    // A block found to be immediately invalid should not end up in fork choice.
                    assert_eq!(block_in_forkchoice, None);

                    assert!(
                        self.harness
                            .chain
                            .get_blinded_block(&block_root)
                            .unwrap()
                            .is_none(),
                        "invalid block cannot be accessed via get_block"
                    );
                } else {
                    // A block imported and then found invalid should have an invalid status.
                    assert!(block_in_forkchoice.unwrap().execution_status.is_invalid());
                }
            }
        }

        block_root
    }

    async fn invalidate_manually(&self, block_root: Hash256) {
        self.harness
            .chain
            .process_invalid_execution_payload(&InvalidationOperation::InvalidateOne { block_root })
            .await
            .unwrap();
    }
}

/// Simple test of the different import types.
#[tokio::test]
async fn valid_invalid_syncing() {
    let mut rig = InvalidPayloadRig::new();
    rig.move_to_terminal_block();

    rig.import_block(Payload::Valid).await;
    rig.import_block(Payload::Invalid {
        latest_valid_hash: None,
    })
    .await;
    rig.import_block(Payload::Syncing).await;
}

/// Ensure that an invalid payload can invalidate its parent too (given the right
/// `latest_valid_hash`.
#[tokio::test]
async fn invalid_payload_invalidates_parent() {
    let mut rig = InvalidPayloadRig::new().enable_attestations();
    rig.move_to_terminal_block();
    rig.import_block(Payload::Valid).await; // Import a valid transition block.
    rig.move_to_first_justification(Payload::Syncing).await;

    let roots = vec![
        rig.import_block(Payload::Syncing).await,
        rig.import_block(Payload::Syncing).await,
        rig.import_block(Payload::Syncing).await,
    ];

    let latest_valid_hash = rig.block_hash(roots[0]);

    rig.import_block(Payload::Invalid {
        latest_valid_hash: Some(latest_valid_hash),
    })
    .await;

    assert!(rig.execution_status(roots[0]).is_valid_and_post_bellatrix());
    assert!(rig.execution_status(roots[1]).is_invalid());
    assert!(rig.execution_status(roots[2]).is_invalid());

    assert_eq!(rig.harness.head_block_root(), roots[0]);
}

/// Test invalidation of a payload via the fork choice updated message.
///
/// The `invalid_payload` argument determines the type of invalid payload: `Invalid`,
/// `InvalidBlockHash`, etc, taking the `latest_valid_hash` as an argument.
async fn immediate_forkchoice_update_invalid_test(
    invalid_payload: impl FnOnce(Option<ExecutionBlockHash>) -> Payload,
) {
    let mut rig = InvalidPayloadRig::new().enable_attestations();
    rig.move_to_terminal_block();
    rig.import_block(Payload::Valid).await; // Import a valid transition block.
    rig.move_to_first_justification(Payload::Syncing).await;

    let valid_head_root = rig.import_block(Payload::Valid).await;
    let latest_valid_hash = Some(rig.block_hash(valid_head_root));

    // Import a block which returns syncing when supplied via newPayload, and then
    // invalid when the forkchoice update is sent.
    rig.import_block_parametric(Payload::Syncing, invalid_payload(latest_valid_hash), |_| {
        false
    })
    .await;

    // The head should be the latest valid block.
    assert_eq!(rig.harness.head_block_root(), valid_head_root);
}

#[tokio::test]
async fn immediate_forkchoice_update_payload_invalid() {
    immediate_forkchoice_update_invalid_test(|latest_valid_hash| Payload::Invalid {
        latest_valid_hash,
    })
    .await
}

#[tokio::test]
async fn immediate_forkchoice_update_payload_invalid_block_hash() {
    immediate_forkchoice_update_invalid_test(|_| Payload::InvalidBlockHash).await
}

#[tokio::test]
async fn immediate_forkchoice_update_payload_invalid_terminal_block() {
    immediate_forkchoice_update_invalid_test(|_| Payload::InvalidTerminalBlock).await
}

/// Ensure the client tries to exit when the justified checkpoint is invalidated.
#[tokio::test]
async fn justified_checkpoint_becomes_invalid() {
    let mut rig = InvalidPayloadRig::new().enable_attestations();
    rig.move_to_terminal_block();
    rig.import_block(Payload::Valid).await; // Import a valid transition block.
    rig.move_to_first_justification(Payload::Syncing).await;

    let justified_checkpoint = rig.harness.justified_checkpoint();
    let parent_root_of_justified = rig
        .harness
        .chain
        .get_blinded_block(&justified_checkpoint.root)
        .unwrap()
        .unwrap()
        .parent_root();
    let parent_hash_of_justified = rig.block_hash(parent_root_of_justified);

    // No service should have triggered a shutdown, yet.
    assert!(rig.harness.shutdown_reasons().is_empty());

    // Import a block that will invalidate the justified checkpoint.
    let is_valid = Payload::Invalid {
        latest_valid_hash: Some(parent_hash_of_justified),
    };
    rig.import_block_parametric(is_valid, is_valid, |error| {
        matches!(
            error,
            // The block import should fail since the beacon chain knows the justified payload
            // is invalid.
            BlockError::BeaconChainError(BeaconChainError::JustifiedPayloadInvalid { .. })
        )
    })
    .await;

    // The beacon chain should have triggered a shutdown.
    assert_eq!(
        rig.harness.shutdown_reasons(),
        vec![ShutdownReason::Failure(
            INVALID_JUSTIFIED_PAYLOAD_SHUTDOWN_REASON
        )]
    );
}

/// Ensure that a `latest_valid_hash` for a pre-finality block only reverts a single block.
#[tokio::test]
async fn pre_finalized_latest_valid_hash() {
    let num_blocks = E::slots_per_epoch() * 4;
    let finalized_epoch = 2;

    let mut rig = InvalidPayloadRig::new().enable_attestations();
    rig.move_to_terminal_block();
    let mut blocks = vec![];
    blocks.push(rig.import_block(Payload::Valid).await); // Import a valid transition block.
    blocks.extend(rig.build_blocks(num_blocks - 1, Payload::Syncing).await);

    assert_eq!(rig.harness.finalized_checkpoint().epoch, finalized_epoch);

    let pre_finalized_block_root = rig.block_root_at_slot(Slot::new(1)).unwrap();
    let pre_finalized_block_hash = rig.block_hash(pre_finalized_block_root);

    // No service should have triggered a shutdown, yet.
    assert!(rig.harness.shutdown_reasons().is_empty());

    // Import a pre-finalized block.
    rig.import_block(Payload::Invalid {
        latest_valid_hash: Some(pre_finalized_block_hash),
    })
    .await;

    // The latest imported block should be the head.
    assert_eq!(rig.harness.head_block_root(), *blocks.last().unwrap());

    // The beacon chain should *not* have triggered a shutdown.
    assert_eq!(rig.harness.shutdown_reasons(), vec![]);

    // All blocks should still be unverified.
    for i in E::slots_per_epoch() * finalized_epoch..num_blocks {
        let slot = Slot::new(i);
        let root = rig.block_root_at_slot(slot).unwrap();
        if slot == 1 {
            assert!(rig.execution_status(root).is_valid_and_post_bellatrix());
        } else {
            assert!(rig.execution_status(root).is_optimistic());
        }
    }
}

/// Ensure that a `latest_valid_hash` will:
///
/// - Invalidate descendants of `latest_valid_root`.
/// - Validate `latest_valid_root` and its ancestors.
#[tokio::test]
async fn latest_valid_hash_will_validate() {
    const LATEST_VALID_SLOT: u64 = 3;

    let mut rig = InvalidPayloadRig::new().enable_attestations();
    rig.move_to_terminal_block();

    let mut blocks = vec![];
    blocks.push(rig.import_block(Payload::Valid).await); // Import a valid transition block.
    blocks.extend(rig.build_blocks(4, Payload::Syncing).await);

    let latest_valid_root = rig
        .block_root_at_slot(Slot::new(LATEST_VALID_SLOT))
        .unwrap();
    let latest_valid_hash = rig.block_hash(latest_valid_root);

    rig.import_block(Payload::Invalid {
        latest_valid_hash: Some(latest_valid_hash),
    })
    .await;

    assert_eq!(rig.harness.head_slot(), LATEST_VALID_SLOT);

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
            assert!(execution_status.is_valid_and_post_bellatrix())
        }
    }
}

/// Check behaviour when the `latest_valid_hash` is a junk value.
#[tokio::test]
async fn latest_valid_hash_is_junk() {
    let num_blocks = E::slots_per_epoch() * 5;
    let finalized_epoch = 3;

    let mut rig = InvalidPayloadRig::new().enable_attestations();
    rig.move_to_terminal_block();
    let mut blocks = vec![];
    blocks.push(rig.import_block(Payload::Valid).await); // Import a valid transition block.
    blocks.extend(rig.build_blocks(num_blocks, Payload::Syncing).await);

    assert_eq!(rig.harness.finalized_checkpoint().epoch, finalized_epoch);

    // No service should have triggered a shutdown, yet.
    assert!(rig.harness.shutdown_reasons().is_empty());

    let junk_hash = ExecutionBlockHash::repeat_byte(42);
    rig.import_block(Payload::Invalid {
        latest_valid_hash: Some(junk_hash),
    })
    .await;

    // The latest imported block should be the head.
    assert_eq!(rig.harness.head_block_root(), *blocks.last().unwrap());

    // The beacon chain should *not* have triggered a shutdown.
    assert_eq!(rig.harness.shutdown_reasons(), vec![]);

    // All blocks should still be unverified.
    for i in E::slots_per_epoch() * finalized_epoch..num_blocks {
        let slot = Slot::new(i);
        let root = rig.block_root_at_slot(slot).unwrap();
        if slot == 1 {
            assert!(rig.execution_status(root).is_valid_and_post_bellatrix());
        } else {
            assert!(rig.execution_status(root).is_optimistic());
        }
    }
}

/// Check that descendants of invalid blocks are also invalidated.
#[tokio::test]
async fn invalidates_all_descendants() {
    let num_blocks = E::slots_per_epoch() * 4 + E::slots_per_epoch() / 2;
    let finalized_epoch = 2;
    let finalized_slot = E::slots_per_epoch() * 2;

    let mut rig = InvalidPayloadRig::new().enable_attestations();
    rig.move_to_terminal_block();
    rig.import_block(Payload::Valid).await; // Import a valid transition block.
    let blocks = rig.build_blocks(num_blocks, Payload::Syncing).await;

    assert_eq!(rig.harness.finalized_checkpoint().epoch, finalized_epoch);
    assert_eq!(rig.harness.head_block_root(), *blocks.last().unwrap());

    // Apply a block which conflicts with the canonical chain.
    let fork_slot = Slot::new(4 * E::slots_per_epoch() + 3);
    let fork_parent_slot = fork_slot - 1;
    let fork_parent_state = rig
        .harness
        .chain
        .state_at_slot(fork_parent_slot, StateSkipConfig::WithStateRoots)
        .unwrap();
    assert_eq!(fork_parent_state.slot(), fork_parent_slot);
    let (fork_block, _fork_post_state) = rig.harness.make_block(fork_parent_state, fork_slot).await;
    let fork_block_root = rig
        .harness
        .chain
        .process_block(Arc::new(fork_block))
        .await
        .unwrap();
    rig.recompute_head().await;

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
    assert_eq!(rig.harness.head_block_root(), *blocks.last().unwrap());

    rig.import_block(Payload::Invalid {
        latest_valid_hash: Some(latest_valid_hash),
    })
    .await;

    // The block before the fork should become the head.
    assert_eq!(rig.harness.head_block_root(), latest_valid_root);

    // The fork block should be invalidated, even though it's not an ancestor of the block that
    // triggered the INVALID response from the EL.
    assert!(rig.execution_status(fork_block_root).is_invalid());

    for root in blocks {
        let slot = rig
            .harness
            .chain
            .get_blinded_block(&root)
            .unwrap()
            .unwrap()
            .slot();

        // Fork choice doesn't have info about pre-finalization, nothing to check here.
        if slot < finalized_slot {
            continue;
        }

        let execution_status = rig.execution_status(root);
        if slot <= latest_valid_slot {
            // Blocks prior to the latest valid hash are valid.
            assert!(execution_status.is_valid_and_post_bellatrix());
        } else {
            // Blocks after the latest valid hash are invalid.
            assert!(execution_status.is_invalid());
        }
    }
}

/// Check that the head will switch after the canonical branch is invalidated.
#[tokio::test]
async fn switches_heads() {
    let num_blocks = E::slots_per_epoch() * 4 + E::slots_per_epoch() / 2;
    let finalized_epoch = 2;
    let finalized_slot = E::slots_per_epoch() * 2;

    let mut rig = InvalidPayloadRig::new().enable_attestations();
    rig.move_to_terminal_block();
    rig.import_block(Payload::Valid).await; // Import a valid transition block.
    let blocks = rig.build_blocks(num_blocks, Payload::Syncing).await;

    assert_eq!(rig.harness.finalized_checkpoint().epoch, finalized_epoch);
    assert_eq!(rig.harness.head_block_root(), *blocks.last().unwrap());

    // Apply a block which conflicts with the canonical chain.
    let fork_slot = Slot::new(4 * E::slots_per_epoch() + 3);
    let fork_parent_slot = fork_slot - 1;
    let fork_parent_state = rig
        .harness
        .chain
        .state_at_slot(fork_parent_slot, StateSkipConfig::WithStateRoots)
        .unwrap();
    assert_eq!(fork_parent_state.slot(), fork_parent_slot);
    let (fork_block, _fork_post_state) = rig.harness.make_block(fork_parent_state, fork_slot).await;
    let fork_parent_root = fork_block.parent_root();
    let fork_block_root = rig
        .harness
        .chain
        .process_block(Arc::new(fork_block))
        .await
        .unwrap();
    rig.recompute_head().await;

    let latest_valid_slot = fork_parent_slot;
    let latest_valid_hash = rig.block_hash(fork_parent_root);

    // The new block should not become the head, the old head should remain.
    assert_eq!(rig.harness.head_block_root(), *blocks.last().unwrap());

    rig.import_block(Payload::Invalid {
        latest_valid_hash: Some(latest_valid_hash),
    })
    .await;

    // The fork block should become the head.
    assert_eq!(rig.harness.head_block_root(), fork_block_root);

    // The fork block has not yet been validated.
    assert!(rig.execution_status(fork_block_root).is_optimistic());

    for root in blocks {
        let slot = rig
            .harness
            .chain
            .get_blinded_block(&root)
            .unwrap()
            .unwrap()
            .slot();

        // Fork choice doesn't have info about pre-finalization, nothing to check here.
        if slot < finalized_slot {
            continue;
        }

        let execution_status = rig.execution_status(root);
        if slot <= latest_valid_slot {
            // Blocks prior to the latest valid hash are valid.
            assert!(execution_status.is_valid_and_post_bellatrix());
        } else {
            // Blocks after the latest valid hash are invalid.
            assert!(execution_status.is_invalid());
        }
    }
}

#[tokio::test]
async fn invalid_during_processing() {
    let mut rig = InvalidPayloadRig::new();
    rig.move_to_terminal_block();

    let roots = &[
        rig.import_block(Payload::Valid).await,
        rig.import_block(Payload::Invalid {
            latest_valid_hash: None,
        })
        .await,
        rig.import_block(Payload::Valid).await,
    ];

    // 0 should be present in the chain.
    assert!(rig
        .harness
        .chain
        .get_blinded_block(&roots[0])
        .unwrap()
        .is_some());
    // 1 should *not* be present in the chain.
    assert_eq!(
        rig.harness.chain.get_blinded_block(&roots[1]).unwrap(),
        None
    );
    // 2 should be the head.
    let head_block_root = rig.harness.head_block_root();
    assert_eq!(head_block_root, roots[2]);
}

#[tokio::test]
async fn invalid_after_optimistic_sync() {
    let mut rig = InvalidPayloadRig::new().enable_attestations();
    rig.move_to_terminal_block();
    rig.import_block(Payload::Valid).await; // Import a valid transition block.

    let mut roots = vec![
        rig.import_block(Payload::Syncing).await,
        rig.import_block(Payload::Syncing).await,
        rig.import_block(Payload::Syncing).await,
    ];

    for root in &roots {
        assert!(rig.harness.chain.get_blinded_block(root).unwrap().is_some());
    }

    // 2 should be the head.
    let head = rig.harness.head_block_root();
    assert_eq!(head, roots[2]);

    roots.push(
        rig.import_block(Payload::Invalid {
            latest_valid_hash: Some(rig.block_hash(roots[1])),
        })
        .await,
    );

    // Running fork choice is necessary since a block has been invalidated.
    rig.recompute_head().await;

    // 1 should be the head, since 2 was invalidated.
    let head = rig.harness.head_block_root();
    assert_eq!(head, roots[1]);
}

#[tokio::test]
async fn manually_validate_child() {
    let mut rig = InvalidPayloadRig::new().enable_attestations();
    rig.move_to_terminal_block();
    rig.import_block(Payload::Valid).await; // Import a valid transition block.

    let parent = rig.import_block(Payload::Syncing).await;
    let child = rig.import_block(Payload::Syncing).await;

    assert!(rig.execution_status(parent).is_optimistic());
    assert!(rig.execution_status(child).is_optimistic());

    rig.validate_manually(child);

    assert!(rig.execution_status(parent).is_valid_and_post_bellatrix());
    assert!(rig.execution_status(child).is_valid_and_post_bellatrix());
}

#[tokio::test]
async fn manually_validate_parent() {
    let mut rig = InvalidPayloadRig::new().enable_attestations();
    rig.move_to_terminal_block();
    rig.import_block(Payload::Valid).await; // Import a valid transition block.

    let parent = rig.import_block(Payload::Syncing).await;
    let child = rig.import_block(Payload::Syncing).await;

    assert!(rig.execution_status(parent).is_optimistic());
    assert!(rig.execution_status(child).is_optimistic());

    rig.validate_manually(parent);

    assert!(rig.execution_status(parent).is_valid_and_post_bellatrix());
    assert!(rig.execution_status(child).is_optimistic());
}

#[tokio::test]
async fn payload_preparation() {
    let mut rig = InvalidPayloadRig::new();
    rig.move_to_terminal_block();
    rig.import_block(Payload::Valid).await;

    let el = rig.execution_layer();
    let head = rig.harness.chain.head_snapshot();
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
    el.update_proposer_preparation(
        Epoch::new(1),
        &[ProposerPreparationData {
            validator_index: proposer as u64,
            fee_recipient,
        }],
    )
    .await;

    rig.harness
        .chain
        .prepare_beacon_proposer(rig.harness.chain.slot().unwrap())
        .await
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

#[tokio::test]
async fn invalid_parent() {
    let mut rig = InvalidPayloadRig::new();
    rig.move_to_terminal_block();
    rig.import_block(Payload::Valid).await; // Import a valid transition block.

    // Import a syncing block atop the transition block (we'll call this the "parent block" since we
    // build another block on it later).
    let parent_root = rig.import_block(Payload::Syncing).await;
    let parent_block = rig.harness.get_block(parent_root.into()).unwrap();
    let parent_state = rig
        .harness
        .get_hot_state(parent_block.state_root().into())
        .unwrap();

    // Produce another block atop the parent, but don't import yet.
    let slot = parent_block.slot() + 1;
    rig.harness.set_current_slot(slot);
    let (block, state) = rig.harness.make_block(parent_state, slot).await;
    let block = Arc::new(block);
    let block_root = block.canonical_root();
    assert_eq!(block.parent_root(), parent_root);

    // Invalidate the parent block.
    rig.invalidate_manually(parent_root).await;
    assert!(rig.execution_status(parent_root).is_invalid());

    // Ensure the block built atop an invalid payload is invalid for gossip.
    assert!(matches!(
        rig.harness.chain.clone().verify_block_for_gossip(block.clone()).await,
        Err(BlockError::ParentExecutionPayloadInvalid { parent_root: invalid_root })
        if invalid_root == parent_root
    ));

    // Ensure the block built atop an invalid payload is invalid for import.
    assert!(matches!(
        rig.harness.chain.process_block(block.clone()).await,
        Err(BlockError::ParentExecutionPayloadInvalid { parent_root: invalid_root })
        if invalid_root == parent_root
    ));

    // Ensure the block built atop an invalid payload cannot be imported to fork choice.
    assert!(matches!(
        rig.harness.chain.canonical_head.fork_choice_write_lock().on_block(
            slot,
            block.message(),
            block_root,
            Duration::from_secs(0),
            &state,
            PayloadVerificationStatus::Optimistic,
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
#[tokio::test]
async fn payload_preparation_before_transition_block() {
    let rig = InvalidPayloadRig::new();
    let el = rig.execution_layer();

    let head = rig.harness.chain.head_snapshot();
    assert_eq!(
        head.beacon_block
            .message()
            .body()
            .execution_payload()
            .unwrap()
            .block_hash(),
        ExecutionBlockHash::zero(),
        "the head block is post-bellatrix but pre-transition"
    );

    let current_slot = rig.harness.chain.slot().unwrap();
    let next_slot = current_slot + 1;
    let proposer = head
        .beacon_state
        .get_beacon_proposer_index(next_slot, &rig.harness.chain.spec)
        .unwrap();
    let fee_recipient = Address::repeat_byte(99);

    // Provide preparation data to the EL for `proposer`.
    el.update_proposer_preparation(
        Epoch::new(0),
        &[ProposerPreparationData {
            validator_index: proposer as u64,
            fee_recipient,
        }],
    )
    .await;

    rig.move_to_terminal_block();

    rig.harness
        .chain
        .prepare_beacon_proposer(current_slot)
        .await
        .unwrap();
    let forkchoice_update_params = rig
        .harness
        .chain
        .canonical_head
        .fork_choice_read_lock()
        .get_forkchoice_update_parameters();
    rig.harness
        .chain
        .update_execution_engine_forkchoice(current_slot, forkchoice_update_params)
        .await
        .unwrap();

    let (fork_choice_state, payload_attributes) = rig.previous_forkchoice_update_params();
    let latest_block_hash = rig.latest_execution_block_hash();
    assert_eq!(payload_attributes.suggested_fee_recipient, fee_recipient);
    assert_eq!(fork_choice_state.head_block_hash, latest_block_hash);
}

#[tokio::test]
async fn attesting_to_optimistic_head() {
    let mut rig = InvalidPayloadRig::new();
    rig.move_to_terminal_block();
    rig.import_block(Payload::Valid).await; // Import a valid transition block.

    let root = rig.import_block(Payload::Syncing).await;

    let head = rig.harness.chain.head_snapshot();
    let slot = head.beacon_block.slot();
    assert_eq!(
        head.beacon_block_root, root,
        "the head should be the latest imported block"
    );
    assert!(
        rig.execution_status(root).is_optimistic(),
        "the head should be optimistic"
    );

    /*
     * Define an attestation for use during testing. It doesn't have a valid signature, but that's
     * not necessary here.
     */

    let attestation = {
        let mut attestation = rig
            .harness
            .chain
            .produce_unaggregated_attestation(Slot::new(0), 0)
            .unwrap();

        attestation.aggregation_bits.set(0, true).unwrap();
        attestation.data.slot = slot;
        attestation.data.beacon_block_root = root;

        rig.harness
            .chain
            .naive_aggregation_pool
            .write()
            .insert(&attestation)
            .unwrap();

        attestation
    };

    /*
     * Define some closures to produce attestations.
     */

    let produce_unaggregated = || rig.harness.chain.produce_unaggregated_attestation(slot, 0);

    let get_aggregated = || {
        rig.harness
            .chain
            .get_aggregated_attestation(&attestation.data)
    };

    let get_aggregated_by_slot_and_root = || {
        rig.harness
            .chain
            .get_aggregated_attestation_by_slot_and_root(
                attestation.data.slot,
                &attestation.data.tree_hash_root(),
            )
    };

    /*
     * Ensure attestation production fails with an optimistic head.
     */

    macro_rules! assert_head_block_not_fully_verified {
        ($func: expr) => {
            assert!(matches!(
                $func,
                Err(BeaconChainError::HeadBlockNotFullyVerified {
                    beacon_block_root,
                    execution_status
                })
                if beacon_block_root == root && matches!(execution_status, ExecutionStatus::Optimistic(_))
            ));
        }
    }

    assert_head_block_not_fully_verified!(produce_unaggregated());
    assert_head_block_not_fully_verified!(get_aggregated());
    assert_head_block_not_fully_verified!(get_aggregated_by_slot_and_root());

    /*
     * Ensure attestation production succeeds once the head is verified.
     *
     * This is effectively a control for the previous tests.
     */

    rig.validate_manually(root);
    assert!(
        rig.execution_status(root).is_valid_and_post_bellatrix(),
        "the head should no longer be optimistic"
    );

    produce_unaggregated().unwrap();
    get_aggregated().unwrap();
    get_aggregated_by_slot_and_root().unwrap();
}
