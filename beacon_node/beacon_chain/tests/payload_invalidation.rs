#![cfg(not(debug_assertions))]

use beacon_chain::otb_verification_service::{
    load_optimistic_transition_blocks, validate_optimistic_transition_blocks,
    OptimisticTransitionBlock,
};
use beacon_chain::{
    canonical_head::{CachedHead, CanonicalHead},
    test_utils::{BeaconChainHarness, EphemeralHarnessType},
    BeaconChainError, BlockError, ExecutionPayloadError, NotifyExecutionLayer, StateSkipConfig,
    WhenSlotSkipped, INVALID_FINALIZED_MERGE_TRANSITION_BLOCK_SHUTDOWN_REASON,
    INVALID_JUSTIFIED_PAYLOAD_SHUTDOWN_REASON,
};
use execution_layer::{
    json_structures::{JsonForkchoiceStateV1, JsonPayloadAttributes, JsonPayloadAttributesV1},
    test_utils::ExecutionBlockGenerator,
    ExecutionLayer, ForkchoiceState, PayloadAttributes,
};
use fork_choice::{
    CountUnrealized, Error as ForkChoiceError, InvalidationOperation, PayloadVerificationStatus,
};
use proto_array::{Error as ProtoArrayError, ExecutionStatus};
use slot_clock::SlotClock;
use std::collections::HashMap;
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
}

struct InvalidPayloadRig {
    harness: BeaconChainHarness<EphemeralHarnessType<E>>,
    enable_attestations: bool,
}

impl InvalidPayloadRig {
    fn new() -> Self {
        let spec = E::default_spec();
        Self::new_with_spec(spec)
    }

    fn new_with_spec(mut spec: ChainSpec) -> Self {
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
        self.harness.chain.recompute_head_at_current_slot().await;
    }

    fn cached_head(&self) -> CachedHead<E> {
        self.harness.chain.canonical_head.cached_head()
    }

    fn canonical_head(&self) -> &CanonicalHead<EphemeralHarnessType<E>> {
        &self.harness.chain.canonical_head
    }

    fn previous_forkchoice_update_params(&self) -> (ForkchoiceState, PayloadAttributes) {
        let mock_execution_layer = self.harness.mock_execution_layer.as_ref().unwrap();
        let json = mock_execution_layer
            .server
            .take_previous_request()
            .expect("no previous request");
        let params = json.get("params").expect("no params");

        let fork_choice_state_json = params.get(0).expect("no payload param");
        let fork_choice_state: JsonForkchoiceStateV1 =
            serde_json::from_value(fork_choice_state_json.clone()).unwrap();

        let payload_param_json = params.get(1).expect("no payload param");
        let attributes: JsonPayloadAttributesV1 =
            serde_json::from_value(payload_param_json.clone()).unwrap();

        (
            fork_choice_state.into(),
            JsonPayloadAttributes::V1(attributes).into(),
        )
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
        self.import_block_parametric(is_valid, is_valid, None, |error| {
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
        slot_override: Option<Slot>,
        evaluate_error: F,
    ) -> Hash256 {
        let mock_execution_layer = self.harness.mock_execution_layer.as_ref().unwrap();

        let head = self.harness.chain.head_snapshot();
        let state = head.beacon_state.clone_with_only_committee_caches();
        let slot = slot_override.unwrap_or(state.slot() + 1);
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
                if latest_valid_hash == ExecutionBlockHash::zero() {
                    mock_execution_layer
                        .server
                        .all_payloads_invalid_terminal_block_on_new_payload()
                } else {
                    mock_execution_layer
                        .server
                        .all_payloads_invalid_on_new_payload(latest_valid_hash)
                }
            }

            Payload::InvalidBlockHash => mock_execution_layer
                .server
                .all_payloads_invalid_block_hash_on_new_payload(),
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
                if latest_valid_hash == ExecutionBlockHash::zero() {
                    mock_execution_layer
                        .server
                        .all_payloads_invalid_terminal_block_on_forkchoice_updated()
                } else {
                    mock_execution_layer
                        .server
                        .all_payloads_invalid_on_forkchoice_updated(latest_valid_hash)
                }
            }

            Payload::InvalidBlockHash => mock_execution_layer
                .server
                .all_payloads_invalid_block_hash_on_forkchoice_updated(),
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
                    .process_block(slot, block.canonical_root(), block.clone())
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
                    Payload::Syncing => assert!(execution_status.is_strictly_optimistic()),
                    Payload::Valid => assert!(execution_status.is_valid_and_post_bellatrix()),
                    Payload::Invalid { .. } | Payload::InvalidBlockHash => unreachable!(),
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
            (Payload::Invalid { .. } | Payload::InvalidBlockHash, _)
            | (_, Payload::Invalid { .. } | Payload::InvalidBlockHash) => {
                set_new_payload(new_payload_response);
                set_forkchoice_updated(forkchoice_response);

                match self
                    .harness
                    .process_block(slot, block.canonical_root(), block)
                    .await
                {
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

    fn assert_get_head_error_contains(&self, s: &str) {
        match self
            .harness
            .chain
            .canonical_head
            .fork_choice_write_lock()
            .get_head(self.harness.chain.slot().unwrap(), &self.harness.chain.spec)
        {
            Err(ForkChoiceError::ProtoArrayError(e)) if e.contains(s) => (),
            other => panic!("expected {} error, got {:?}", s, other),
        };
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

    assert!(rig.execution_status(roots[0]).is_strictly_optimistic());
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
    rig.import_block_parametric(
        Payload::Syncing,
        invalid_payload(latest_valid_hash),
        None,
        |_| false,
    )
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
    immediate_forkchoice_update_invalid_test(|_| Payload::Invalid {
        latest_valid_hash: Some(ExecutionBlockHash::zero()),
    })
    .await
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
    rig.import_block_parametric(is_valid, is_valid, None, |error| {
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
            assert!(rig.execution_status(root).is_strictly_optimistic());
        }
    }
}

/// Ensure that a `latest_valid_hash` will:
///
/// - Invalidate descendants of `latest_valid_root`.
/// - Will not validate `latest_valid_root` and its ancestors.
#[tokio::test]
async fn latest_valid_hash_will_not_validate() {
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
        } else if slot == 1 {
            assert!(execution_status.is_valid_and_post_bellatrix())
        } else {
            assert!(execution_status.is_strictly_optimistic())
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
            assert!(rig.execution_status(root).is_strictly_optimistic());
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
        .process_block(
            fork_block.canonical_root(),
            Arc::new(fork_block),
            CountUnrealized::True,
            NotifyExecutionLayer::Yes,
        )
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
        if slot == 0 {
            // Genesis block is pre-bellatrix.
            assert!(execution_status.is_irrelevant());
        } else if slot == 1 {
            // First slot was imported as valid.
            assert!(execution_status.is_valid_and_post_bellatrix());
        } else if slot <= latest_valid_slot {
            // Blocks prior to and included the latest valid hash are not marked as valid.
            assert!(execution_status.is_strictly_optimistic());
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
        .process_block(
            fork_block.canonical_root(),
            Arc::new(fork_block),
            CountUnrealized::True,
            NotifyExecutionLayer::Yes,
        )
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
    assert!(rig
        .execution_status(fork_block_root)
        .is_strictly_optimistic());

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
        if slot == 0 {
            // Genesis block is pre-bellatrix.
            assert!(execution_status.is_irrelevant());
        } else if slot == 1 {
            // First slot was imported as valid.
            assert!(execution_status.is_valid_and_post_bellatrix());
        } else if slot <= latest_valid_slot {
            // Blocks prior to and included the latest valid hash are not marked as valid.
            assert!(execution_status.is_strictly_optimistic());
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

    assert!(rig.execution_status(parent).is_strictly_optimistic());
    assert!(rig.execution_status(child).is_strictly_optimistic());

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

    assert!(rig.execution_status(parent).is_strictly_optimistic());
    assert!(rig.execution_status(child).is_strictly_optimistic());

    rig.validate_manually(parent);

    assert!(rig.execution_status(parent).is_valid_and_post_bellatrix());
    assert!(rig.execution_status(child).is_strictly_optimistic());
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

    let payload_attributes = PayloadAttributes::new(
        rig.harness
            .chain
            .slot_clock
            .start_of(next_slot)
            .unwrap()
            .as_secs(),
        *head
            .beacon_state
            .get_randao_mix(head.beacon_state.current_epoch())
            .unwrap(),
        fee_recipient,
        None,
    )
    .downgrade_to_v1()
    .unwrap();
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
        rig.harness.chain.process_block(block.canonical_root(), block.clone(), CountUnrealized::True, NotifyExecutionLayer::Yes).await,
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
            &rig.harness.chain.spec,
            CountUnrealized::True,
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

    // Run the watchdog routine so that the status of the execution engine is set. This ensures
    // that we don't end up with `eth_syncing` requests later in this function that will impede
    // testing.
    el.watchdog_task().await;

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
    assert_eq!(payload_attributes.suggested_fee_recipient(), fee_recipient);
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
        rig.execution_status(root).is_strictly_optimistic(),
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

/// A helper struct to build out a chain of some configurable length which undergoes the merge
/// transition.
struct OptimisticTransitionSetup {
    blocks: Vec<Arc<SignedBeaconBlock<E>>>,
    execution_block_generator: ExecutionBlockGenerator<E>,
}

impl OptimisticTransitionSetup {
    async fn new(num_blocks: usize, ttd: u64) -> Self {
        let mut spec = E::default_spec();
        spec.terminal_total_difficulty = ttd.into();
        let mut rig = InvalidPayloadRig::new_with_spec(spec).enable_attestations();
        rig.move_to_terminal_block();

        let mut blocks = Vec::with_capacity(num_blocks);
        for _ in 0..num_blocks {
            let root = rig.import_block(Payload::Valid).await;
            let block = rig.harness.chain.get_block(&root).await.unwrap().unwrap();
            blocks.push(Arc::new(block));
        }

        let execution_block_generator = rig
            .harness
            .mock_execution_layer
            .as_ref()
            .unwrap()
            .server
            .execution_block_generator()
            .clone();

        Self {
            blocks,
            execution_block_generator,
        }
    }
}

/// Build a chain which has optimistically imported a transition block.
///
/// The initial chain will be built with respect to `block_ttd`, whilst the `rig` which imports the
/// chain will operate with respect to `rig_ttd`. This allows for testing mismatched TTDs.
async fn build_optimistic_chain(
    block_ttd: u64,
    rig_ttd: u64,
    num_blocks: usize,
) -> InvalidPayloadRig {
    let OptimisticTransitionSetup {
        blocks,
        execution_block_generator,
    } = OptimisticTransitionSetup::new(num_blocks, block_ttd).await;
    // Build a brand-new testing harness. We will apply the blocks from the previous harness to
    // this one.
    let mut spec = E::default_spec();
    spec.terminal_total_difficulty = rig_ttd.into();
    let rig = InvalidPayloadRig::new_with_spec(spec);

    let spec = &rig.harness.chain.spec;
    let mock_execution_layer = rig.harness.mock_execution_layer.as_ref().unwrap();

    // Ensure all the execution blocks from the first rig are available in the second rig.
    *mock_execution_layer.server.execution_block_generator() = execution_block_generator;

    // Make the execution layer respond `SYNCING` to all `newPayload` requests.
    mock_execution_layer
        .server
        .all_payloads_syncing_on_new_payload(true);
    // Make the execution layer respond `SYNCING` to all `forkchoiceUpdated` requests.
    mock_execution_layer
        .server
        .all_payloads_syncing_on_forkchoice_updated();
    // Make the execution layer respond `None` to all `getBlockByHash` requests.
    mock_execution_layer
        .server
        .all_get_block_by_hash_requests_return_none();

    let current_slot = std::cmp::max(
        blocks[0].slot() + spec.safe_slots_to_import_optimistically,
        num_blocks.into(),
    );
    rig.harness.set_current_slot(current_slot);

    for block in blocks {
        rig.harness
            .chain
            .process_block(
                block.canonical_root(),
                block,
                CountUnrealized::True,
                NotifyExecutionLayer::Yes,
            )
            .await
            .unwrap();
    }

    rig.harness.chain.recompute_head_at_current_slot().await;

    // Make the execution layer respond normally to `getBlockByHash` requests.
    mock_execution_layer
        .server
        .all_get_block_by_hash_requests_return_natural_value();

    // Perform some sanity checks to ensure that the transition happened exactly where we expected.
    let pre_transition_block_root = rig
        .harness
        .chain
        .block_root_at_slot(Slot::new(0), WhenSlotSkipped::None)
        .unwrap()
        .unwrap();
    let pre_transition_block = rig
        .harness
        .chain
        .get_block(&pre_transition_block_root)
        .await
        .unwrap()
        .unwrap();
    let post_transition_block_root = rig
        .harness
        .chain
        .block_root_at_slot(Slot::new(1), WhenSlotSkipped::None)
        .unwrap()
        .unwrap();
    let post_transition_block = rig
        .harness
        .chain
        .get_block(&post_transition_block_root)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        pre_transition_block_root,
        post_transition_block.parent_root(),
        "the blocks form a single chain"
    );
    assert!(
        pre_transition_block
            .message()
            .body()
            .execution_payload()
            .unwrap()
            .is_default_with_empty_roots(),
        "the block *has not* undergone the merge transition"
    );
    assert!(
        !post_transition_block
            .message()
            .body()
            .execution_payload()
            .unwrap()
            .is_default_with_empty_roots(),
        "the block *has* undergone the merge transition"
    );

    // Assert that the transition block was optimistically imported.
    //
    // Note: we're using the "fallback" check for optimistic status, so if the block was
    // pre-finality then we'll just use the optimistic status of the finalized block.
    assert!(
        rig.harness
            .chain
            .canonical_head
            .fork_choice_read_lock()
            .is_optimistic_or_invalid_block(&post_transition_block_root)
            .unwrap(),
        "the transition block should be imported optimistically"
    );

    // Get the mock execution layer to respond to `getBlockByHash` requests normally again.
    mock_execution_layer
        .server
        .all_get_block_by_hash_requests_return_natural_value();

    return rig;
}

#[tokio::test]
async fn optimistic_transition_block_valid_unfinalized() {
    let ttd = 42;
    let num_blocks = 16 as usize;
    let rig = build_optimistic_chain(ttd, ttd, num_blocks).await;

    let post_transition_block_root = rig
        .harness
        .chain
        .block_root_at_slot(Slot::new(1), WhenSlotSkipped::None)
        .unwrap()
        .unwrap();
    let post_transition_block = rig
        .harness
        .chain
        .get_block(&post_transition_block_root)
        .await
        .unwrap()
        .unwrap();

    assert!(
        rig.cached_head()
            .finalized_checkpoint()
            .epoch
            .start_slot(E::slots_per_epoch())
            < post_transition_block.slot(),
        "the transition block should not be finalized"
    );

    let otbs = load_optimistic_transition_blocks(&rig.harness.chain)
        .expect("should load optimistic transition block from db");
    assert_eq!(
        otbs.len(),
        1,
        "There should be one optimistic transition block"
    );
    let valid_otb = OptimisticTransitionBlock::from_block(post_transition_block.message());
    assert_eq!(
        valid_otb, otbs[0],
        "The optimistic transition block stored in the database should be what we expect",
    );

    validate_optimistic_transition_blocks(&rig.harness.chain, otbs)
        .await
        .expect("should validate fine");
    // now that the transition block has been validated, it should have been removed from the database
    let otbs = load_optimistic_transition_blocks(&rig.harness.chain)
        .expect("should load optimistic transition block from db");
    assert!(
        otbs.is_empty(),
        "The valid optimistic transition block should have been removed from the database",
    );
}

#[tokio::test]
async fn optimistic_transition_block_valid_finalized() {
    let ttd = 42;
    let num_blocks = 130 as usize;
    let rig = build_optimistic_chain(ttd, ttd, num_blocks).await;

    let post_transition_block_root = rig
        .harness
        .chain
        .block_root_at_slot(Slot::new(1), WhenSlotSkipped::None)
        .unwrap()
        .unwrap();
    let post_transition_block = rig
        .harness
        .chain
        .get_block(&post_transition_block_root)
        .await
        .unwrap()
        .unwrap();

    assert!(
        rig.cached_head()
            .finalized_checkpoint()
            .epoch
            .start_slot(E::slots_per_epoch())
            > post_transition_block.slot(),
        "the transition block should be finalized"
    );

    let otbs = load_optimistic_transition_blocks(&rig.harness.chain)
        .expect("should load optimistic transition block from db");
    assert_eq!(
        otbs.len(),
        1,
        "There should be one optimistic transition block"
    );
    let valid_otb = OptimisticTransitionBlock::from_block(post_transition_block.message());
    assert_eq!(
        valid_otb, otbs[0],
        "The optimistic transition block stored in the database should be what we expect",
    );

    validate_optimistic_transition_blocks(&rig.harness.chain, otbs)
        .await
        .expect("should validate fine");
    // now that the transition block has been validated, it should have been removed from the database
    let otbs = load_optimistic_transition_blocks(&rig.harness.chain)
        .expect("should load optimistic transition block from db");
    assert!(
        otbs.is_empty(),
        "The valid optimistic transition block should have been removed from the database",
    );
}

#[tokio::test]
async fn optimistic_transition_block_invalid_unfinalized() {
    let block_ttd = 42;
    let rig_ttd = 1337;
    let num_blocks = 22 as usize;
    let rig = build_optimistic_chain(block_ttd, rig_ttd, num_blocks).await;

    let post_transition_block_root = rig
        .harness
        .chain
        .block_root_at_slot(Slot::new(1), WhenSlotSkipped::None)
        .unwrap()
        .unwrap();
    let post_transition_block = rig
        .harness
        .chain
        .get_block(&post_transition_block_root)
        .await
        .unwrap()
        .unwrap();

    assert!(
        rig.cached_head()
            .finalized_checkpoint()
            .epoch
            .start_slot(E::slots_per_epoch())
            < post_transition_block.slot(),
        "the transition block should not be finalized"
    );

    let otbs = load_optimistic_transition_blocks(&rig.harness.chain)
        .expect("should load optimistic transition block from db");
    assert_eq!(
        otbs.len(),
        1,
        "There should be one optimistic transition block"
    );

    let invalid_otb = OptimisticTransitionBlock::from_block(post_transition_block.message());
    assert_eq!(
        invalid_otb, otbs[0],
        "The optimistic transition block stored in the database should be what we expect",
    );

    // No shutdown should've been triggered.
    assert_eq!(rig.harness.shutdown_reasons(), vec![]);
    // It shouldn't be known as invalid yet
    assert!(!rig
        .execution_status(post_transition_block_root)
        .is_invalid());

    validate_optimistic_transition_blocks(&rig.harness.chain, otbs)
        .await
        .unwrap();

    // Still no shutdown should've been triggered.
    assert_eq!(rig.harness.shutdown_reasons(), vec![]);
    // It should be marked invalid now
    assert!(rig
        .execution_status(post_transition_block_root)
        .is_invalid());

    // the invalid merge transition block should NOT have been removed from the database
    let otbs = load_optimistic_transition_blocks(&rig.harness.chain)
        .expect("should load optimistic transition block from db");
    assert_eq!(
        otbs.len(),
        1,
        "The invalid merge transition block should still be in the database",
    );
    assert_eq!(
        invalid_otb, otbs[0],
        "The optimistic transition block stored in the database should be what we expect",
    );
}

#[tokio::test]
async fn optimistic_transition_block_invalid_unfinalized_syncing_ee() {
    let block_ttd = 42;
    let rig_ttd = 1337;
    let num_blocks = 22 as usize;
    let rig = build_optimistic_chain(block_ttd, rig_ttd, num_blocks).await;

    let post_transition_block_root = rig
        .harness
        .chain
        .block_root_at_slot(Slot::new(1), WhenSlotSkipped::None)
        .unwrap()
        .unwrap();
    let post_transition_block = rig
        .harness
        .chain
        .get_block(&post_transition_block_root)
        .await
        .unwrap()
        .unwrap();

    assert!(
        rig.cached_head()
            .finalized_checkpoint()
            .epoch
            .start_slot(E::slots_per_epoch())
            < post_transition_block.slot(),
        "the transition block should not be finalized"
    );

    let otbs = load_optimistic_transition_blocks(&rig.harness.chain)
        .expect("should load optimistic transition block from db");
    assert_eq!(
        otbs.len(),
        1,
        "There should be one optimistic transition block"
    );

    let invalid_otb = OptimisticTransitionBlock::from_block(post_transition_block.message());
    assert_eq!(
        invalid_otb, otbs[0],
        "The optimistic transition block stored in the database should be what we expect",
    );

    // No shutdown should've been triggered.
    assert_eq!(rig.harness.shutdown_reasons(), vec![]);
    // It shouldn't be known as invalid yet
    assert!(!rig
        .execution_status(post_transition_block_root)
        .is_invalid());

    // Make the execution layer respond `None` to all `getBlockByHash` requests to simulate a
    // syncing EE.
    let mock_execution_layer = rig.harness.mock_execution_layer.as_ref().unwrap();
    mock_execution_layer
        .server
        .all_get_block_by_hash_requests_return_none();

    validate_optimistic_transition_blocks(&rig.harness.chain, otbs)
        .await
        .unwrap();

    // Still no shutdown should've been triggered.
    assert_eq!(rig.harness.shutdown_reasons(), vec![]);

    // It should still be marked as optimistic.
    assert!(rig
        .execution_status(post_transition_block_root)
        .is_strictly_optimistic());

    // the optimistic merge transition block should NOT have been removed from the database
    let otbs = load_optimistic_transition_blocks(&rig.harness.chain)
        .expect("should load optimistic transition block from db");
    assert_eq!(
        otbs.len(),
        1,
        "The optimistic merge transition block should still be in the database",
    );
    assert_eq!(
        invalid_otb, otbs[0],
        "The optimistic transition block stored in the database should be what we expect",
    );

    // Allow the EL to respond to `getBlockByHash`, as if it has finished syncing.
    mock_execution_layer
        .server
        .all_get_block_by_hash_requests_return_natural_value();

    validate_optimistic_transition_blocks(&rig.harness.chain, otbs)
        .await
        .unwrap();

    // Still no shutdown should've been triggered.
    assert_eq!(rig.harness.shutdown_reasons(), vec![]);
    // It should be marked invalid now
    assert!(rig
        .execution_status(post_transition_block_root)
        .is_invalid());

    // the invalid merge transition block should NOT have been removed from the database
    let otbs = load_optimistic_transition_blocks(&rig.harness.chain)
        .expect("should load optimistic transition block from db");
    assert_eq!(
        otbs.len(),
        1,
        "The invalid merge transition block should still be in the database",
    );
    assert_eq!(
        invalid_otb, otbs[0],
        "The optimistic transition block stored in the database should be what we expect",
    );
}

#[tokio::test]
async fn optimistic_transition_block_invalid_finalized() {
    let block_ttd = 42;
    let rig_ttd = 1337;
    let num_blocks = 130 as usize;
    let rig = build_optimistic_chain(block_ttd, rig_ttd, num_blocks).await;

    let post_transition_block_root = rig
        .harness
        .chain
        .block_root_at_slot(Slot::new(1), WhenSlotSkipped::None)
        .unwrap()
        .unwrap();
    let post_transition_block = rig
        .harness
        .chain
        .get_block(&post_transition_block_root)
        .await
        .unwrap()
        .unwrap();

    assert!(
        rig.cached_head()
            .finalized_checkpoint()
            .epoch
            .start_slot(E::slots_per_epoch())
            > post_transition_block.slot(),
        "the transition block should be finalized"
    );

    let otbs = load_optimistic_transition_blocks(&rig.harness.chain)
        .expect("should load optimistic transition block from db");

    assert_eq!(
        otbs.len(),
        1,
        "There should be one optimistic transition block"
    );

    let invalid_otb = OptimisticTransitionBlock::from_block(post_transition_block.message());
    assert_eq!(
        invalid_otb, otbs[0],
        "The optimistic transition block stored in the database should be what we expect",
    );

    // No shutdown should've been triggered yet.
    assert_eq!(rig.harness.shutdown_reasons(), vec![]);

    validate_optimistic_transition_blocks(&rig.harness.chain, otbs)
        .await
        .expect("should invalidate merge transition block and shutdown the client");

    // The beacon chain should have triggered a shutdown.
    assert_eq!(
        rig.harness.shutdown_reasons(),
        vec![ShutdownReason::Failure(
            INVALID_FINALIZED_MERGE_TRANSITION_BLOCK_SHUTDOWN_REASON
        )]
    );

    // the invalid merge transition block should NOT have been removed from the database
    let otbs = load_optimistic_transition_blocks(&rig.harness.chain)
        .expect("should load optimistic transition block from db");
    assert_eq!(
        otbs.len(),
        1,
        "The invalid merge transition block should still be in the database",
    );
    assert_eq!(
        invalid_otb, otbs[0],
        "The optimistic transition block stored in the database should be what we expect",
    );
}

/// Helper for running tests where we generate a chain with an invalid head and then a
/// `fork_block` to recover it.
struct InvalidHeadSetup {
    rig: InvalidPayloadRig,
    fork_block: Arc<SignedBeaconBlock<E>>,
    invalid_head: CachedHead<E>,
}

impl InvalidHeadSetup {
    async fn new() -> InvalidHeadSetup {
        let mut rig = InvalidPayloadRig::new().enable_attestations();
        rig.move_to_terminal_block();
        rig.import_block(Payload::Valid).await; // Import a valid transition block.

        // Import blocks until the first time the chain finalizes.
        while rig.cached_head().finalized_checkpoint().epoch == 0 {
            rig.import_block(Payload::Syncing).await;
        }

        let slots_per_epoch = E::slots_per_epoch();
        let start_slot = rig.cached_head().head_slot() + 1;
        let mut opt_fork_block = None;

        assert_eq!(start_slot % slots_per_epoch, 1);
        for i in 0..slots_per_epoch - 1 {
            let slot = start_slot + i;
            let slot_offset = slot.as_u64() % slots_per_epoch;

            rig.harness.set_current_slot(slot);

            if slot_offset == slots_per_epoch - 1 {
                // Optimistic head block right before epoch boundary.
                let is_valid = Payload::Syncing;
                rig.import_block_parametric(is_valid, is_valid, Some(slot), |error| {
                    matches!(
                        error,
                        BlockError::ExecutionPayloadError(
                            ExecutionPayloadError::RejectedByExecutionEngine { .. }
                        )
                    )
                })
                .await;
            } else if 3 * slot_offset < 2 * slots_per_epoch {
                // Valid block in previous epoch.
                rig.import_block(Payload::Valid).await;
            } else if slot_offset == slots_per_epoch - 2 {
                // Fork block one slot prior to invalid head, not applied immediately.
                let parent_state = rig
                    .harness
                    .chain
                    .state_at_slot(slot - 1, StateSkipConfig::WithStateRoots)
                    .unwrap();
                let (fork_block, _) = rig.harness.make_block(parent_state, slot).await;
                opt_fork_block = Some(Arc::new(fork_block));
            } else {
                // Skipped slot.
            };
        }

        let invalid_head = rig.cached_head();
        assert_eq!(
            invalid_head.head_slot() % slots_per_epoch,
            slots_per_epoch - 1
        );

        // Advance clock to new epoch to realize the justification of soon-to-be-invalid head block.
        rig.harness.set_current_slot(invalid_head.head_slot() + 1);

        // Invalidate the head block.
        rig.invalidate_manually(invalid_head.head_block_root())
            .await;

        assert!(rig
            .canonical_head()
            .head_execution_status()
            .unwrap()
            .is_invalid());

        // Finding a new head should fail since the only possible head is not valid.
        rig.assert_get_head_error_contains("InvalidBestNode");

        Self {
            rig,
            fork_block: opt_fork_block.unwrap(),
            invalid_head,
        }
    }
}

#[tokio::test]
async fn recover_from_invalid_head_by_importing_blocks() {
    let InvalidHeadSetup {
        rig,
        fork_block,
        invalid_head: _,
    } = InvalidHeadSetup::new().await;

    // Import the fork block, it should become the head.
    rig.harness
        .chain
        .process_block(
            fork_block.canonical_root(),
            fork_block.clone(),
            CountUnrealized::True,
            NotifyExecutionLayer::Yes,
        )
        .await
        .unwrap();
    rig.recompute_head().await;
    let new_head = rig.cached_head();
    assert_eq!(
        new_head.head_block_root(),
        fork_block.canonical_root(),
        "the fork block should become the head"
    );

    let manual_get_head = rig
        .harness
        .chain
        .canonical_head
        .fork_choice_write_lock()
        .get_head(rig.harness.chain.slot().unwrap(), &rig.harness.chain.spec)
        .unwrap();
    assert_eq!(manual_get_head, new_head.head_block_root());
}

#[tokio::test]
async fn recover_from_invalid_head_after_persist_and_reboot() {
    let InvalidHeadSetup {
        rig,
        fork_block: _,
        invalid_head,
    } = InvalidHeadSetup::new().await;

    let slot_clock = rig.harness.chain.slot_clock.clone();

    // Forcefully persist the head and fork choice.
    rig.harness.chain.persist_head_and_fork_choice().unwrap();

    let resumed = BeaconChainHarness::builder(MainnetEthSpec)
        .default_spec()
        .deterministic_keypairs(VALIDATOR_COUNT)
        .resumed_ephemeral_store(rig.harness.chain.store.clone())
        .mock_execution_layer()
        .testing_slot_clock(slot_clock)
        .build();

    // Forget the original rig so we don't accidentally use it again.
    drop(rig);

    let resumed_head = resumed.chain.canonical_head.cached_head();
    assert_eq!(
        resumed_head.head_block_root(),
        invalid_head.head_block_root(),
        "the resumed harness should have the invalid block as the head"
    );
    assert!(
        resumed
            .chain
            .canonical_head
            .fork_choice_read_lock()
            .get_block_execution_status(&resumed_head.head_block_root())
            .unwrap()
            .is_strictly_optimistic(),
        "the invalid block should have become optimistic"
    );
}

#[tokio::test]
async fn weights_after_resetting_optimistic_status() {
    let mut rig = InvalidPayloadRig::new().enable_attestations();
    rig.move_to_terminal_block();
    rig.import_block(Payload::Valid).await; // Import a valid transition block.

    let mut roots = vec![];
    for _ in 0..4 {
        roots.push(rig.import_block(Payload::Syncing).await);
    }

    rig.recompute_head().await;
    let head = rig.cached_head();

    let original_weights = rig
        .harness
        .chain
        .canonical_head
        .fork_choice_read_lock()
        .proto_array()
        .iter_nodes(&head.head_block_root())
        .map(|node| (node.root, node.weight))
        .collect::<HashMap<_, _>>();

    rig.invalidate_manually(roots[1]).await;

    rig.harness
        .chain
        .canonical_head
        .fork_choice_write_lock()
        .proto_array_mut()
        .set_all_blocks_to_optimistic::<E>(&rig.harness.chain.spec)
        .unwrap();

    let new_weights = rig
        .harness
        .chain
        .canonical_head
        .fork_choice_read_lock()
        .proto_array()
        .iter_nodes(&head.head_block_root())
        .map(|node| (node.root, node.weight))
        .collect::<HashMap<_, _>>();

    assert_eq!(original_weights, new_weights);

    // Advance the current slot and run fork choice to remove proposer boost.
    rig.harness
        .set_current_slot(rig.harness.chain.slot().unwrap() + 1);
    rig.recompute_head().await;

    assert_eq!(
        rig.harness
            .chain
            .canonical_head
            .fork_choice_read_lock()
            .get_block_weight(&head.head_block_root())
            .unwrap(),
        head.snapshot.beacon_state.validators()[0].effective_balance,
        "proposer boost should be removed from the head block and the vote of a single validator applied"
    );

    // Import a length of chain to ensure the chain can be built atop.
    for _ in 0..E::slots_per_epoch() * 4 {
        rig.import_block(Payload::Valid).await;
    }
}
