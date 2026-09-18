use beacon_chain::{
    observed_operations::ObservationOutcome,
    test_utils::{BeaconChainHarness, test_spec},
};
use std::sync::Arc;
use types::{
    Address, Epoch, ExecutionRequests, ExecutionRequestsGloas, Hash256, MinimalEthSpec, Slot,
    WithdrawalRequest,
};

type E = MinimalEthSpec;

/// Parent partial withdrawals must be accounted for when packing voluntary exits.
/// https://github.com/sigp/lighthouse/issues/9981
#[tokio::test]
async fn gloas_block_production_filters_exits_with_parent_partial_withdrawals() {
    let mut spec = test_spec::<E>();
    if !spec.fork_name_at_slot::<E>(Slot::new(0)).gloas_enabled() {
        return;
    }

    // Allow exits and withdrawal requests without waiting for the activation period.
    spec.shard_committee_period = 0;
    let spec = Arc::new(spec);
    let initial_balance = spec.min_activation_balance * 2;
    let withdrawal_amount = spec.effective_balance_increment;
    let withdrawal_address = Address::repeat_byte(0xaa);

    let harness = BeaconChainHarness::builder(E::default())
        .spec(spec.clone())
        .deterministic_keypairs(64)
        .with_genesis_state_builder(|builder| {
            builder
                .set_initial_balance_fn(Box::new(move |_| initial_balance))
                .set_withdrawal_credentials_fn(Box::new(move |_, _, spec| {
                    let mut credentials = [0; 32];
                    credentials[0] = spec.compounding_withdrawal_prefix_byte;
                    credentials[12..].copy_from_slice(withdrawal_address.as_slice());
                    Hash256::from(credentials)
                }))
        })
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    harness.extend_to_slot(Slot::new(1)).await;

    let mut requests = ExecutionRequestsGloas::<E>::default();
    requests.withdrawals.push(WithdrawalRequest {
        source_address: withdrawal_address,
        validator_pubkey: harness.get_current_state().get_validator(0).unwrap().pubkey,
        amount: withdrawal_amount,
    });
    harness
        .execution_block_generator()
        .set_next_execution_requests(ExecutionRequests::Gloas(requests.clone()));

    // Import the parent block and envelope. Its withdrawal request is deferred until the child.
    harness.extend_to_slot(Slot::new(2)).await;
    let parent_state = harness.get_current_state();
    assert!(
        parent_state
            .pending_partial_withdrawals()
            .unwrap()
            .is_empty()
    );

    for validator_index in [0, 1] {
        let exit = harness.make_voluntary_exit(validator_index, Epoch::new(0));
        let ObservationOutcome::New(verified_exit) = harness
            .chain
            .verify_voluntary_exit_for_gossip(exit)
            .unwrap()
        else {
            panic!("voluntary exit should be newly verified");
        };
        harness.chain.import_voluntary_exit(verified_exit);
    }
    assert_eq!(
        harness
            .chain
            .op_pool
            .get_slashings_and_exits(&parent_state, &spec)
            .2
            .len(),
        2,
        "both exits must be eligible before the parent requests are applied"
    );

    harness.advance_slot();
    let child_slot = Slot::new(3);
    let (block_contents, _, _) = harness
        .make_block_with_envelope(parent_state, child_slot)
        .await;
    let body = block_contents.0.message().body();
    assert_eq!(body.parent_execution_requests().unwrap(), &requests);
    let included_exits: Vec<_> = body
        .voluntary_exits()
        .iter()
        .map(|exit| exit.message.validator_index)
        .collect();
    assert_eq!(included_exits, vec![1]);

    // Import verifies the produced block, including the remaining exit's signature and state root.
    let child_root = block_contents.0.canonical_root();
    harness
        .process_block(child_slot, child_root, block_contents)
        .await
        .expect("block with a parent partial withdrawal should import");
    assert_eq!(
        harness.chain.head_beacon_block().canonical_root(),
        child_root
    );

    let state = harness.get_current_state();
    let pending_withdrawals = state.pending_partial_withdrawals().unwrap();
    assert_eq!(pending_withdrawals.len(), 1);
    let pending_withdrawal = pending_withdrawals.get(0).unwrap();
    assert_eq!(pending_withdrawal.validator_index, 0);
    assert_eq!(pending_withdrawal.amount, withdrawal_amount);
    assert_eq!(
        state.get_validator(0).unwrap().exit_epoch,
        spec.far_future_epoch
    );
    assert_ne!(
        state.get_validator(1).unwrap().exit_epoch,
        spec.far_future_epoch
    );
}
