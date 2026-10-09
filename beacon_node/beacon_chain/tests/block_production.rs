use beacon_chain::{
    BlockProductionError, ProduceBlockVerification,
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
use std::sync::Arc;
use types::{
    Address, BeaconBlock, BeaconState, Checkpoint, Epoch, ExecutionBlockHash, ExecutionPayloadBid,
    ExecutionPayloadBidGloas, ExecutionPayloadBidHeze, ExecutionPayloadHeader,
    ExecutionPayloadHeaderFulu, ExecutionRequests, ExecutionRequestsGloas, Hash256, InclusionList,
    InclusionListBits, ProgressiveTransactions, SignedExecutionPayloadBid,
    SignedExecutionPayloadBidRef, SignedInclusionList, Slot, Spec, WithdrawalRequest,
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
    fn new(heze_at_genesis: bool) -> Option<Self> {
        let mut spec = test_spec::<E>();
        if !spec.fork_name_at_slot::<E>(Slot::new(0)).gloas_enabled() {
            return None;
        }
        if heze_at_genesis {
            spec.heze_fork_epoch = Some(Epoch::new(0));
        }
        let spec = Arc::new(spec);

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

    /// A bid worth `value` from the registered builder. It is a Heze bid claiming
    /// `inclusion_list_bits` when they are given, and a Gloas bid otherwise.
    fn signed_builder_bid(
        &self,
        value: u64,
        inclusion_list_bits: Option<InclusionListBits<E>>,
    ) -> Arc<SignedExecutionPayloadBid<E>> {
        let bid = ExecutionPayloadBidGloas::<E> {
            slot: Slot::new(1),
            builder_index: BUILDER_INDEX,
            value,
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

        let bid = match inclusion_list_bits {
            None => ExecutionPayloadBid::Gloas(bid),
            Some(inclusion_list_bits) => ExecutionPayloadBid::Heze(ExecutionPayloadBidHeze {
                parent_block_hash: bid.parent_block_hash,
                parent_block_root: bid.parent_block_root,
                block_hash: bid.block_hash,
                prev_randao: bid.prev_randao,
                fee_recipient: bid.fee_recipient,
                gas_limit: bid.gas_limit,
                builder_index: bid.builder_index,
                slot: bid.slot,
                value: bid.value,
                execution_payment: bid.execution_payment,
                blob_kzg_commitments: bid.blob_kzg_commitments,
                execution_requests_root: bid.execution_requests_root,
                inclusion_list_bits,
            }),
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
    let Some(rig) = BuilderOnlyProposer::new(false) else {
        return;
    };
    let bid = rig.signed_builder_bid(BID_VALUE, None);
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
    let Some(rig) = BuilderOnlyProposer::new(false) else {
        return;
    };

    match rig.produce_block().await {
        Err(BlockProductionError::NoViablePayloadBid) => {}
        Err(other) => panic!("expected NoViablePayloadBid, got {other:?}"),
        Ok(_) => panic!("a proposer with no execution layer and no bid has nothing to propose"),
    }
}

/// A gossip bid cached before a late inclusion list arrived, whose bits miss that list, is
/// skipped at production, while one covering it is used.
#[tokio::test]
async fn heze_gossip_bid_missing_a_late_inclusion_list_is_skipped_at_production() {
    let Some(rig) = BuilderOnlyProposer::new(true) else {
        return;
    };

    let inclusion_list_slot = Slot::new(0);
    let (committee, dependent_root) = rig
        .harness
        .chain
        .inclusion_list_committee(rig.genesis_block_root, inclusion_list_slot)
        .unwrap();
    let late_submitter = committee[0];
    rig.harness
        .chain
        .inclusion_list_store
        .write()
        .process_inclusion_list(
            SignedInclusionList {
                message: InclusionList {
                    slot: inclusion_list_slot,
                    validator_index: late_submitter,
                    dependent_root,
                    transactions: ProgressiveTransactions::default(),
                },
                signature: Signature::empty(),
            },
            false,
        );

    rig.observe_bid(rig.signed_builder_bid(BID_VALUE, Some(InclusionListBits::<E>::default())));
    match rig.produce_block().await {
        Err(BlockProductionError::NoViablePayloadBid) => {}
        Err(other) => panic!("expected NoViablePayloadBid, got {other:?}"),
        Ok(_) => panic!("a bid missing a held inclusion list must not be used"),
    }

    let mut inclusion_list_bits = InclusionListBits::<E>::default();
    for (position, validator_index) in committee.iter().enumerate() {
        if *validator_index == late_submitter {
            inclusion_list_bits.set(position, true).unwrap();
        }
    }
    let covering_bid = rig.signed_builder_bid(BID_VALUE + 1, Some(inclusion_list_bits));
    rig.observe_bid(covering_bid.clone());

    let block = rig
        .produce_block()
        .await
        .expect("a bid covering every held inclusion list is viable");
    assert_eq!(
        &block
            .body()
            .signed_execution_payload_bid()
            .unwrap()
            .clone_as_signed_execution_payload_bid(),
        covering_bid.as_ref()
    );
}

/// The self-built bid claims every inclusion list the node holds for the slot before the proposal,
/// both timely and untimely.
#[tokio::test]
async fn heze_self_build_bid_claims_held_inclusion_lists() {
    let mut spec = test_spec::<E>();
    if !spec.fork_name_at_slot::<E>(Slot::new(0)).gloas_enabled() {
        return;
    }
    spec.heze_fork_epoch = Some(Epoch::new(0));

    let harness = BeaconChainHarness::builder(E::default())
        .spec(Arc::new(spec))
        .deterministic_keypairs(64)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    let inclusion_list_slot = Slot::new(0);
    let parent_root = harness.head_block_root();
    let (committee, dependent_root) = harness
        .chain
        .inclusion_list_committee(parent_root, inclusion_list_slot)
        .unwrap();

    let timely_submitter = committee[0];
    let late_submitter = *committee
        .iter()
        .find(|index| **index != timely_submitter)
        .unwrap();

    for (validator_index, is_timely) in [(timely_submitter, true), (late_submitter, false)] {
        harness
            .chain
            .inclusion_list_store
            .write()
            .process_inclusion_list(
                SignedInclusionList {
                    message: InclusionList {
                        slot: inclusion_list_slot,
                        validator_index,
                        dependent_root,
                        transactions: ProgressiveTransactions::default(),
                    },
                    signature: Signature::empty(),
                },
                is_timely,
            );
    }

    harness.advance_slot();
    let state = harness.get_current_state();
    let (block_contents, _, _) = harness.make_block_with_envelope(state, Slot::new(1)).await;

    let SignedExecutionPayloadBidRef::Heze(signed_bid) = block_contents
        .0
        .message()
        .body()
        .signed_execution_payload_bid()
        .unwrap()
    else {
        panic!("a Heze block should carry a Heze bid");
    };
    assert_eq!(signed_bid.message.builder_index, BUILDER_INDEX_SELF_BUILD);

    // A validator holding several committee positions has all of them set
    for (position, validator_index) in committee.iter().enumerate() {
        let expected = *validator_index == timely_submitter || *validator_index == late_submitter;
        assert_eq!(
            signed_bid
                .message
                .inclusion_list_bits
                .get(position)
                .unwrap(),
            expected,
            "unexpected bit at committee position {position}"
        );
    }
}
