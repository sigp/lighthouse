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

/// Client-selected bids use the same block construction as V4, with p2p/local fallback.
#[tokio::test]
async fn gloas_block_production_with_supplied_bid() {
    use beacon_chain::{
        BlockProductionBidSource, ProduceBlockVerification, graffiti_calculator::GraffitiSettings,
        payload_bid_verification::gossip_verified_bid::GossipVerifiedPayloadBid,
    };
    use bls::Signature;
    use state_processing::state_advance::complete_state_advance;
    use types::{
        Builder, Domain, EthSpec, ExecutionBlockHash, ExecutionPayloadBid, ForkName,
        SignedExecutionPayloadBid, SignedRoot, Uint256,
        consts::gloas::{BUILDER_INDEX_SELF_BUILD, PAYLOAD_BUILDER_VERSION},
    };

    let spec = Arc::new(ForkName::Gloas.make_genesis_spec(E::default_spec()));
    let harness = BeaconChainHarness::builder(E::default())
        .spec(spec.clone())
        .deterministic_keypairs(32)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();
    harness
        .execution_block_generator()
        .set_generate_blobs(false);
    harness
        .extend_to_slot(Slot::new(E::slots_per_epoch() * 4))
        .await;
    harness.advance_slot();
    let slot = harness.get_current_slot();
    let head = harness.chain.canonical_head.cached_head();
    let parent_root = head.head_block_root();
    let parent_payload_status = head.head_payload_status();
    let parent_envelope = head.snapshot.execution_envelope.clone();
    drop(head);
    assert!(
        harness.chain.is_healthy(&parent_root).unwrap() == execution_layer::ChainHealth::Healthy
    );

    // Add a funded builder to the production state; no mutation of the canonical state is needed
    // because these tests inspect the produced blocks rather than importing them.
    let mut state = harness.get_current_state();
    complete_state_advance(&mut state, None, slot, None, &spec).unwrap();
    let builder_key = &harness.validator_keypairs[0];
    state
        .builders_mut()
        .unwrap()
        .push(Builder {
            pubkey: builder_key.pk.clone().into(),
            version: PAYLOAD_BUILDER_VERSION,
            execution_address: Address::repeat_byte(1),
            balance: spec.min_deposit_amount + 1_000_000_000,
            deposit_epoch: Epoch::new(0),
            withdrawable_epoch: spec.far_future_epoch,
        })
        .unwrap();
    state.build_caches(&spec).unwrap();
    assert!(state.is_active_builder(0, &spec).unwrap());
    let parent_bid = state.latest_execution_payload_bid().unwrap();
    let mut bid = SignedExecutionPayloadBid {
        message: ExecutionPayloadBid::<E> {
            slot,
            parent_block_hash: parent_bid.block_hash,
            parent_block_root: parent_root,
            block_hash: ExecutionBlockHash::repeat_byte(42),
            prev_randao: *state.get_randao_mix(state.current_epoch()).unwrap(),
            gas_limit: parent_bid.gas_limit,
            builder_index: 0,
            value: 1_000_000_000,
            execution_payment: 2_000_000_000,
            ..Default::default()
        },
        signature: Signature::empty(),
    };
    let domain = spec.get_domain(
        state.current_epoch(),
        Domain::BeaconBuilder,
        &spec.fork_at_epoch(state.current_epoch()),
        state.genesis_validators_root(),
    );
    bid.signature = builder_key.sk.sign(bid.message.signing_root(domain));
    let proposer_index = state.get_beacon_proposer_index(slot, &spec).unwrap();
    let randao_reveal = harness.sign_randao_reveal(&state, proposer_index, slot);

    for case in [
        "valid",
        "prefer_local",
        "wrong_slot",
        "wrong_parent",
        "bad_signature",
        "p2p_fallback",
        "circuit_breaker",
    ] {
        let mut supplied = bid.clone();
        match case {
            "wrong_slot" => supplied.message.slot += 1,
            "wrong_parent" => supplied.message.parent_block_root = Hash256::repeat_byte(99),
            "bad_signature" | "p2p_fallback" => supplied.signature = Signature::empty(),
            _ => {}
        }
        if case == "p2p_fallback" {
            let mut gossip_bid = bid.clone();
            gossip_bid.message.execution_payment = 0;
            gossip_bid.signature = builder_key.sk.sign(gossip_bid.message.signing_root(domain));
            harness
                .chain
                .gossip_verified_payload_bid_cache
                .observe_bid(GossipVerifiedPayloadBid {
                    signed_bid: Arc::new(gossip_bid),
                });
        }
        if case == "circuit_breaker" {
            // Leave the valid gossip fallback cached too; neither external bid may be used.
            harness.chain.slot_clock.set_slot(slot.as_u64() + 10);
            assert!(
                harness.chain.is_healthy(&parent_root).unwrap()
                    != execution_layer::ChainHealth::Healthy
            );
        }
        let (block, _, _, value, payload, builder_url) = harness
            .chain
            .produce_block_on_state_gloas(
                state.clone(),
                None,
                parent_root,
                parent_payload_status,
                parent_envelope.clone(),
                slot,
                randao_reveal.clone(),
                GraffitiSettings::new(None, None),
                ProduceBlockVerification::VerifyRandao,
                BlockProductionBidSource::ApiSupplied {
                    signed_bid: Arc::new(supplied),
                    builder_boost_factor: if case == "prefer_local" { 0 } else { u64::MAX },
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{case}: {error:?}"));
        let produced_bid = block.body().signed_execution_payload_bid().unwrap().clone();
        if matches!(case, "valid" | "p2p_fallback") {
            assert_eq!(produced_bid.message.builder_index, 0, "{case}");
            assert_eq!(produced_bid.message.block_hash, bid.message.block_hash);
            assert!(payload.is_none());
            let expected_gwei = if case == "valid" {
                3_000_000_000u64
            } else {
                1_000_000_000
            };
            assert_eq!(
                value,
                Uint256::from(expected_gwei) * Uint256::from(1_000_000_000u64)
            );
        } else {
            assert_eq!(
                produced_bid.message.builder_index, BUILDER_INDEX_SELF_BUILD,
                "{case}"
            );
            assert!(payload.is_some());
        }
        assert!(builder_url.is_none());
    }
}
