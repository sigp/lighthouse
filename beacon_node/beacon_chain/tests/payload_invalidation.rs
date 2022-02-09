// #![cfg(not(debug_assertions))]

use beacon_chain::{
    test_utils::{BeaconChainHarness, EphemeralHarnessType},
    BeaconChainError, BlockError, ExecutionPayloadError, HeadInfo, WhenSlotSkipped,
    INVALID_JUSTIFIED_PAYLOAD_SHUTDOWN_REASON,
};
use proto_array::ExecutionStatus;
use task_executor::ShutdownReason;
use types::*;

const VALIDATOR_COUNT: usize = 32;

type E = MainnetEthSpec;

#[derive(PartialEq, Clone)]
enum Payload {
    Valid,
    Invalid { latest_valid_hash: Option<Hash256> },
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

    fn block_hash(&self, block_root: Hash256) -> Hash256 {
        self.harness
            .chain
            .get_block(&block_root)
            .unwrap()
            .unwrap()
            .message()
            .body()
            .execution_payload()
            .unwrap()
            .block_hash
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

    fn move_to_terminal_block(&self) {
        let mock_execution_layer = self.harness.mock_execution_layer.as_ref().unwrap();
        mock_execution_layer
            .server
            .execution_block_generator()
            .move_to_terminal_block()
            .unwrap();
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
                BlockError::ExecutionPayloadError(ExecutionPayloadError::RejectedByExecutionEngine)
            )
        })
    }

    fn block_root_at_slot(&self, slot: Slot) -> Option<Hash256> {
        self.harness
            .chain
            .block_root_at_slot(slot, WhenSlotSkipped::None)
            .unwrap()
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
                    mock_execution_layer.server.all_payloads_syncing();
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
                        panic!("expected invalid payload, got {:?}", other)
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
}

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

#[test]
fn invalid_payload_invalidates_parent() {
    let mut rig = InvalidPayloadRig::new();
    rig.move_to_terminal_block();

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

#[test]
fn justified_checkpoint_becomes_invalid() {
    let mut rig = InvalidPayloadRig::new().enable_attestations();
    rig.move_to_terminal_block();
    rig.move_to_first_justification(Payload::Syncing);

    let justified_checkpoint = rig.head_info().current_justified_checkpoint;
    let parent_root_of_justified = rig
        .harness
        .chain
        .get_block(&justified_checkpoint.root)
        .unwrap()
        .unwrap()
        .parent_root();

    // No service should have triggered a shutdown, yet.
    assert!(rig.harness.shutdown_reasons().is_empty());

    // Import a block that will invalidate the justified checkpoint.
    rig.import_block_parametric(
        Payload::Invalid {
            latest_valid_hash: Some(parent_root_of_justified),
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

#[test]
fn pre_finalized_latest_valid_hash() {
    let mut rig = InvalidPayloadRig::new().enable_attestations();
    rig.move_to_terminal_block();
    rig.build_blocks(E::slots_per_epoch() * 4, Payload::Syncing);

    assert_eq!(rig.head_info().finalized_checkpoint.epoch, 2);

    let pre_finalized_block_root = rig.block_root_at_slot(Slot::new(1)).unwrap();

    // No service should have triggered a shutdown, yet.
    assert!(rig.harness.shutdown_reasons().is_empty());

    // Import a block that will invalidate the justified checkpoint.
    rig.import_block_parametric(
        Payload::Invalid {
            latest_valid_hash: Some(pre_finalized_block_root),
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

/*
 * TODO: test with a junk `latest_valid_hash`.
 */

#[test]
fn latest_valid_hash_will_validate() {
    const LATEST_VALID_SLOT: u64 = 3;

    let mut rig = InvalidPayloadRig::new().enable_attestations();
    rig.move_to_terminal_block();
    let blocks = rig.build_blocks(4, Payload::Syncing);

    let latest_valid_root = rig
        .block_root_at_slot(Slot::new(LATEST_VALID_SLOT))
        .unwrap();
    let latest_valid_hash = rig.block_hash(latest_valid_root);

    rig.import_block(Payload::Invalid {
        latest_valid_hash: Some(latest_valid_hash),
    });

    assert_eq!(rig.head_info().slot, LATEST_VALID_SLOT);

    for slot in 0..=4 {
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
        } else {
            assert!(execution_status.is_valid())
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
    let mut rig = InvalidPayloadRig::new();
    rig.move_to_terminal_block();

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
