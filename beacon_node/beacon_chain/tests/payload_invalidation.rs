// #![cfg(not(debug_assertions))]

use beacon_chain::{
    test_utils::{BeaconChainHarness, EphemeralHarnessType},
    BlockError, ExecutionPayloadError,
};
use std::collections::HashSet;
use types::*;

const VALIDATOR_COUNT: usize = 32;

type E = MainnetEthSpec;

enum Payload {
    Valid,
    Invalid,
}

struct InvalidPayloadRig {
    harness: BeaconChainHarness<EphemeralHarnessType<E>>,
    valid_blocks: HashSet<Hash256>,
    invalid_blocks: HashSet<Hash256>,
}

impl InvalidPayloadRig {
    fn new() -> Self {
        let mut spec = E::default_spec();
        spec.altair_fork_epoch = Some(Epoch::new(0));
        spec.merge_fork_epoch = Some(Epoch::new(0));

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
            valid_blocks: <_>::default(),
            invalid_blocks: <_>::default(),
        }
    }

    fn move_to_terminal_block(&self) {
        let mock_execution_layer = self.harness.mock_execution_layer.as_ref().unwrap();
        mock_execution_layer
            .server
            .execution_block_generator()
            .move_to_terminal_block()
            .unwrap();
    }

    fn import_block(&mut self, is_valid: Payload) -> Hash256 {
        let mock_execution_layer = self.harness.mock_execution_layer.as_ref().unwrap();

        let head = self.harness.chain.head().unwrap();
        let state = head.beacon_state;
        let slot = state.slot() + 1;
        let (block, _post_state) = self.harness.make_block(state, slot);
        let block_root = block.canonical_root();

        match is_valid {
            Payload::Valid => {
                mock_execution_layer.server.full_payload_verification();
                self.harness.process_block(slot, block.clone()).unwrap();
                self.valid_blocks.insert(block_root);
            }
            Payload::Invalid => {
                let parent = self
                    .harness
                    .chain
                    .get_block(&block.message().parent_root())
                    .unwrap()
                    .unwrap();
                let parent_payload = parent.message().body().execution_payload().unwrap();
                mock_execution_layer
                    .server
                    .all_payloads_invalid(parent_payload.block_hash);

                match self.harness.process_block(slot, block.clone()) {
                    Err(BlockError::ExecutionPayloadError(
                        ExecutionPayloadError::RejectedByExecutionEngine,
                    )) => (),
                    Err(other) => {
                        panic!("expected invalid payload, got {:?}", other)
                    }
                    Ok(_) => panic!("block with invalid payload was imported"),
                };
                self.invalid_blocks.insert(block_root);
            }
        }

        block_root
    }
}

#[test]
fn invalid_during_processing() {
    let mut rig = InvalidPayloadRig::new();
    rig.move_to_terminal_block();

    let roots = &[
        rig.import_block(Payload::Valid),
        rig.import_block(Payload::Invalid),
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
