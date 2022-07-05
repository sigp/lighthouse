use beacon_chain::{
    test_utils::{AttestationStrategy, BeaconChainHarness, BlockStrategy},
    WhenSlotSkipped,
};
use types::*;

const VALIDATOR_COUNT: usize = 24;

#[tokio::test]
async fn chooses_highest_justified_checkpoint() {
    let slots_per_epoch = MainnetEthSpec::slots_per_epoch();
    let mut spec = MainnetEthSpec::default_spec();
    spec.altair_fork_epoch = Some(Epoch::new(0));
    let harness = BeaconChainHarness::builder(MainnetEthSpec)
        .spec(spec)
        .deterministic_keypairs(VALIDATOR_COUNT)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    harness.advance_slot();

    let head = harness.chain.head_snapshot();
    assert_eq!(head.beacon_block.slot(), 0, "the chain head is at genesis");
    assert_eq!(
        head.beacon_state.finalized_checkpoint().epoch,
        0,
        "there has been no finalization yet"
    );

    let slot_a = Slot::from(slots_per_epoch * 4 + slots_per_epoch - 1);
    harness
        .extend_chain(
            slot_a.as_usize(),
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let head = harness.chain.head_snapshot();
    assert_eq!(head.beacon_block.slot(), slot_a);
    assert_eq!(
        head.beacon_block.slot() % slots_per_epoch,
        slots_per_epoch - 1,
        "the chain is at the last slot of the epoch"
    );
    assert_eq!(
        head.beacon_state.current_justified_checkpoint().epoch,
        3,
        "the chain has justified"
    );
    assert_eq!(
        head.beacon_state.finalized_checkpoint().epoch,
        2,
        "the chain has finalized"
    );
    let slot_a_root = head.beacon_block_root;

    let reorg_distance = 9;
    let fork_parent_slot = slot_a - reorg_distance;
    let fork_parent_block = harness
        .chain
        .block_at_slot(fork_parent_slot, WhenSlotSkipped::None)
        .unwrap()
        .unwrap();
    let fork_parent_state = harness
        .chain
        .get_state(&fork_parent_block.state_root(), Some(fork_parent_slot))
        .unwrap()
        .unwrap();
    let (fork_block, fork_state) = harness.make_block(fork_parent_state, slot_a + 1).await;

    assert_eq!(
        fork_state.current_justified_checkpoint().epoch,
        4,
        "the fork block has justifed further"
    );
    assert_eq!(
        fork_state.finalized_checkpoint().epoch,
        3,
        "the fork block has finalized further"
    );

    let fork_block_root = fork_block.canonical_root();
    assert_eq!(
        fork_block_root,
        harness
            .process_block(fork_block.slot(), fork_block)
            .await
            .unwrap()
            .into()
    );

    {
        let fork_choice = harness.chain.canonical_head.fork_choice_read_lock();
        let proto_array = fork_choice.proto_array();
        assert_eq!(
            proto_array.get_weight(&fork_block_root).unwrap(),
            0,
            "the fork block should have no votes"
        );
        assert!(
            proto_array.get_weight(&slot_a_root).unwrap() > 0,
            "the slot_a block should have some votes"
        );
    }

    let head = harness.chain.head_snapshot();
    assert_eq!(
        head.beacon_block_root, slot_a_root,
        "the fork block has not become the head"
    );
}
