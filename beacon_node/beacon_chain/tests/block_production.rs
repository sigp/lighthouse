use beacon_chain::{
    BlockProductionBidSource, BlockProductionError, ProduceBlockVerification,
    graffiti_calculator::GraffitiSettings,
    observed_operations::ObservationOutcome,
    payload_bid_verification::gossip_verified_bid::GossipVerifiedPayloadBid,
    test_utils::{BeaconChainHarness, EphemeralHarnessType, test_spec},
};
use bls::{PublicKeyBytes, Signature};
use eth2::types::{BuilderConfig, GraffitiPolicy};
use ethereum_hashing::hash;
use genesis::{generate_deterministic_keypairs, interop_genesis_state};
use proto_array::PayloadStatus;
use ssz::Encode;
use state_processing::state_advance::complete_state_advance;
use std::sync::Arc;
use types::{
    Address, BeaconBlock, BeaconState, Builder, Checkpoint, Epoch, EthSpec, ExecutionBlockHash,
    ExecutionPayloadBidGloas, ExecutionPayloadHeader, ExecutionPayloadHeaderFulu,
    ExecutionRequests, ExecutionRequestsGloas, Hash256, SignedExecutionPayloadBid,
    SignedExecutionPayloadBidGloas, Slot, Spec, Uint256, WithdrawalRequest,
    consts::gloas::{BUILDER_INDEX_SELF_BUILD, PAYLOAD_BUILDER_VERSION},
};

type E = Spec;

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
    requests
        .withdrawals
        .push(WithdrawalRequest {
            source_address: withdrawal_address,
            validator_pubkey: harness.get_current_state().get_validator(0).unwrap().pubkey,
            amount: withdrawal_amount,
        })
        .unwrap();
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
    let spec = test_spec::<E>();
    if !spec.fork_name_at_slot::<E>(Slot::new(0)).gloas_enabled() {
        return;
    }
    let spec = Arc::new(spec);
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
    let bid = ExecutionPayloadBidGloas::<E> {
        slot,
        parent_block_hash: parent_bid.block_hash(),
        parent_block_root: parent_root,
        block_hash: ExecutionBlockHash::repeat_byte(42),
        prev_randao: *state.get_randao_mix(state.current_epoch()).unwrap(),
        gas_limit: parent_bid.gas_limit(),
        builder_index: 0,
        value: 1_000_000_000,
        execution_payment: 2_000_000_000,
        ..Default::default()
    };
    let proposer_index = state.get_beacon_proposer_index(slot, &spec).unwrap();
    let randao_reveal = harness.sign_randao_reveal(&state, proposer_index, slot);

    for case in [
        "valid",
        "prefer_local",
        "wrong_slot",
        "wrong_parent",
        "bad_signature",
        "p2p_fallback",
    ] {
        let mut supplied = bid.clone();
        match case {
            "wrong_slot" => supplied.slot += 1,
            "wrong_parent" => supplied.parent_block_root = Hash256::repeat_byte(99),
            _ => {}
        }
        let supplied = if matches!(case, "bad_signature" | "p2p_fallback") {
            Arc::new(SignedExecutionPayloadBid::Gloas(
                SignedExecutionPayloadBidGloas {
                    message: supplied,
                    signature: Signature::empty(),
                },
            ))
        } else {
            harness.sign_payload_bid(supplied, &state)
        };
        if case == "p2p_fallback" {
            let mut gossip_bid = bid.clone();
            gossip_bid.execution_payment = 0;
            harness
                .chain
                .gossip_verified_payload_bid_cache
                .observe_bid(GossipVerifiedPayloadBid {
                    signed_bid: harness.sign_payload_bid(gossip_bid, &state),
                });
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
                    signed_bid: supplied,
                    builder_boost_factor: if case == "prefer_local" { 0 } else { u64::MAX },
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{case}: {error:?}"));
        let produced_bid = block
            .body()
            .signed_execution_payload_bid()
            .unwrap()
            .clone_as_signed_execution_payload_bid();
        if matches!(case, "valid" | "p2p_fallback") {
            assert_eq!(produced_bid.message().builder_index(), 0, "{case}");
            assert_eq!(produced_bid.message().block_hash(), bid.block_hash);
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
                produced_bid.message().builder_index(),
                BUILDER_INDEX_SELF_BUILD,
                "{case}"
            );
            assert!(payload.is_some());
        }
        assert!(builder_url.is_none());
    }
}

const BUILDER_INDEX: u64 = 0;
const BUILDER_BALANCE: u64 = 2_000_000_000;
const BID_VALUE: u64 = 1_000_000;
const GENESIS_GAS_LIMIT: u64 = 30_000_000;

/// A Gloas node running with no execution layer, proposing at slot 1 on top of genesis.
struct BuilderOnlyProposer {
    harness: BeaconChainHarness<EphemeralHarnessType<E>>,
    state: BeaconState<E>,
    genesis_block_root: Hash256,
    genesis_state_root: Hash256,
}

impl BuilderOnlyProposer {
    /// Returns `None` when the fork under test is not Gloas.
    fn new() -> Option<Self> {
        let spec = Arc::new(test_spec::<E>());
        if !spec.fork_name_at_slot::<E>(Slot::new(0)).gloas_enabled() {
            return None;
        }

        let keypairs = generate_deterministic_keypairs(64);
        // Gloas has no payload header, so seed genesis with the last pre-Gloas one and let the
        // genesis upgrades convert it.
        let execution_payload_header = ExecutionPayloadHeader::Fulu(ExecutionPayloadHeaderFulu {
            block_hash: ExecutionBlockHash::repeat_byte(0x42),
            gas_limit: GENESIS_GAS_LIMIT,
            ..Default::default()
        });
        let mut genesis_state = interop_genesis_state::<E>(
            &keypairs,
            0,
            Hash256::repeat_byte(0x42),
            Some(execution_payload_header),
            &spec,
        )
        .expect("should build genesis state");

        let builder_keypair = &keypairs[BUILDER_INDEX as usize];
        let mut credentials = [0u8; 32];
        credentials[0] = spec.builder_withdrawal_prefix_byte;
        credentials[12..].copy_from_slice(&hash(&builder_keypair.pk.as_ssz_bytes())[0..20]);
        genesis_state
            .add_builder_to_registry(
                PublicKeyBytes::from(builder_keypair.pk.clone()),
                PAYLOAD_BUILDER_VERSION,
                Hash256::from(credentials),
                BUILDER_BALANCE,
                Slot::new(0),
                &spec,
            )
            .expect("should register builder");

        let harness = BeaconChainHarness::builder(E::default())
            .spec(spec)
            .keypairs(keypairs)
            .genesis_state_ephemeral_store(genesis_state)
            .proof_engine()
            .build();
        assert!(
            harness.chain.execution_layer.is_none(),
            "this rig is only meaningful without an execution layer"
        );

        let genesis_block = harness.chain.head_beacon_block();
        let genesis_block_root = genesis_block.canonical_root();
        let genesis_state_root = genesis_block.message().state_root();

        // Finalize only the copy handed to production: a builder is active only once its deposit
        // epoch is behind finalization.
        let mut state = harness.get_current_state();
        *state.finalized_checkpoint_mut() = Checkpoint {
            epoch: Epoch::new(1),
            root: genesis_block_root,
        };

        harness.advance_slot();

        Some(Self {
            harness,
            state,
            genesis_block_root,
            genesis_state_root,
        })
    }

    fn signed_builder_bid(&self) -> Arc<SignedExecutionPayloadBid<E>> {
        let bid = ExecutionPayloadBidGloas::<E> {
            slot: Slot::new(1),
            builder_index: BUILDER_INDEX,
            value: BID_VALUE,
            fee_recipient: Address::repeat_byte(0xbb),
            gas_limit: GENESIS_GAS_LIMIT,
            parent_block_root: self.genesis_block_root,
            parent_block_hash: *self
                .state
                .latest_block_hash()
                .expect("Gloas state should have an execution block hash"),
            prev_randao: *self
                .state
                .get_randao_mix(Epoch::new(0))
                .expect("should read the genesis randao mix"),
            ..Default::default()
        };

        self.harness.sign_payload_bid(bid, &self.state)
    }

    /// Record `bid` as if it had arrived and passed gossip verification.
    fn observe_bid(&self, bid: Arc<SignedExecutionPayloadBid<E>>) {
        assert!(
            self.harness
                .chain
                .gossip_verified_payload_bid_cache
                .observe_bid(GossipVerifiedPayloadBid { signed_bid: bid }),
            "the first bid for a parent is always the highest"
        );
    }

    async fn produce_block(&self) -> Result<BeaconBlock<E>, BlockProductionError> {
        let slot = Slot::new(1);
        let proposer_index = self
            .state
            .get_beacon_proposer_index(slot, &self.harness.spec)
            .expect("should know the slot 1 proposer");

        self.harness
            .chain
            .produce_block_on_state_gloas(
                self.state.clone(),
                Some(self.genesis_state_root),
                self.genesis_block_root,
                PayloadStatus::Empty,
                None,
                slot,
                self.harness
                    .sign_randao_reveal(&self.state, proposer_index, slot),
                GraffitiSettings::new(None, Some(GraffitiPolicy::PreserveUserGraffiti)),
                ProduceBlockVerification::VerifyRandao,
                BuilderConfig::empty(),
            )
            .await
            .map(|(block, ..)| block)
    }
}

/// A node with no execution layer has nothing to build locally, so its proposal rides entirely on
/// a builder's bid.
#[tokio::test]
async fn gloas_block_production_without_an_execution_layer_uses_a_builder_bid() {
    let Some(rig) = BuilderOnlyProposer::new() else {
        return;
    };
    let bid = rig.signed_builder_bid();
    rig.observe_bid(bid.clone());

    let block = rig
        .produce_block()
        .await
        .expect("a bid is all an execution-layer-less proposer needs");

    assert_eq!(
        &block
            .body()
            .signed_execution_payload_bid()
            .expect("a Gloas block carries a bid")
            .clone_as_signed_execution_payload_bid(),
        bid.as_ref(),
        "the proposal must carry the builder's bid, not a local build"
    );
}

/// With no bid such a node has nothing to propose: there is no local build to fall back on.
#[tokio::test]
async fn gloas_block_production_without_an_execution_layer_needs_a_bid() {
    let Some(rig) = BuilderOnlyProposer::new() else {
        return;
    };

    match rig.produce_block().await {
        Err(BlockProductionError::NoViablePayloadBid) => {}
        Err(other) => panic!("expected NoViablePayloadBid, got {other:?}"),
        Ok(_) => panic!("a proposer with no execution layer and no bid has nothing to propose"),
    }
}
