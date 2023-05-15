#![cfg(not(debug_assertions))]

use beacon_chain::attestation_verification::{
    batch_verify_aggregated_attestations, batch_verify_unaggregated_attestations, Error,
};
use beacon_chain::test_utils::{MakeAttestationOptions, HARNESS_GENESIS_TIME};
use beacon_chain::{
    attestation_verification::Error as AttnError,
    test_utils::{
        test_spec, AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
    },
    BeaconChain, BeaconChainError, BeaconChainTypes, WhenSlotSkipped,
};
use genesis::{interop_genesis_state, DEFAULT_ETH1_BLOCK_HASH};
use int_to_bytes::int_to_bytes32;
use lazy_static::lazy_static;
use state_processing::{
    per_block_processing::errors::AttestationValidationError, per_slot_processing,
};
use tree_hash::TreeHash;
use types::{
    test_utils::generate_deterministic_keypair, Address, AggregateSignature, Attestation,
    BeaconStateError, BitList, ChainSpec, Epoch, EthSpec, ForkName, Hash256, Keypair,
    MainnetEthSpec, SecretKey, SelectionProof, SignedAggregateAndProof, Slot, SubnetId, Unsigned,
};

pub type E = MainnetEthSpec;

/// The validator count needs to be relatively high compared to other tests to ensure that we can
/// have committees where _some_ validators are aggregators but not _all_.
pub const VALIDATOR_COUNT: usize = 256;

pub const CAPELLA_FORK_EPOCH: usize = 1;

lazy_static! {
    /// A cached set of keys.
    static ref KEYPAIRS: Vec<Keypair> = types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT);
}

/// Returns a beacon chain harness.
fn get_harness(validator_count: usize) -> BeaconChainHarness<EphemeralHarnessType<E>> {
    let mut spec = test_spec::<E>();

    // A kind-of arbitrary number that ensures that _some_ validators are aggregators, but
    // not all.
    spec.target_aggregators_per_committee = 4;

    let harness = BeaconChainHarness::builder(MainnetEthSpec)
        .spec(spec)
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    harness.advance_slot();

    harness
}

/// Returns a beacon chain harness with Capella fork enabled at epoch 1, and
/// all genesis validators start with BLS withdrawal credentials.
fn get_harness_capella_spec(
    validator_count: usize,
) -> (BeaconChainHarness<EphemeralHarnessType<E>>, ChainSpec) {
    let mut spec = E::default_spec();
    spec.altair_fork_epoch = Some(Epoch::new(0));
    spec.bellatrix_fork_epoch = Some(Epoch::new(0));
    spec.capella_fork_epoch = Some(Epoch::new(CAPELLA_FORK_EPOCH as u64));

    let validator_keypairs = KEYPAIRS[0..validator_count].to_vec();
    let genesis_state = interop_genesis_state(
        &validator_keypairs,
        HARNESS_GENESIS_TIME,
        Hash256::from_slice(DEFAULT_ETH1_BLOCK_HASH),
        None,
        &spec,
    )
    .unwrap();

    let harness = BeaconChainHarness::builder(MainnetEthSpec)
        .spec(spec.clone())
        .keypairs(validator_keypairs)
        .withdrawal_keypairs(
            KEYPAIRS[0..validator_count]
                .iter()
                .cloned()
                .map(Some)
                .collect(),
        )
        .genesis_state_ephemeral_store(genesis_state)
        .mock_execution_layer()
        .build();

    harness
        .execution_block_generator()
        .move_to_terminal_block()
        .unwrap();

    harness.advance_slot();

    (harness, spec)
}

/// Returns an attestation that is valid for some slot in the given `chain`.
///
/// Also returns some info about who created it.
fn get_valid_unaggregated_attestation<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
) -> (Attestation<T::EthSpec>, usize, usize, SecretKey, SubnetId) {
    let head = chain.head_snapshot();
    let current_slot = chain.slot().expect("should get slot");

    let mut valid_attestation = chain
        .produce_unaggregated_attestation(current_slot, 0)
        .expect("should not error while producing attestation");

    let validator_committee_index = 0;
    let validator_index = *head
        .beacon_state
        .get_beacon_committee(current_slot, valid_attestation.data.index)
        .expect("should get committees")
        .committee
        .get(validator_committee_index)
        .expect("there should be an attesting validator");

    let validator_sk = generate_deterministic_keypair(validator_index).sk;

    valid_attestation
        .sign(
            &validator_sk,
            validator_committee_index,
            &head.beacon_state.fork(),
            chain.genesis_validators_root,
            &chain.spec,
        )
        .expect("should sign attestation");

    let subnet_id = SubnetId::compute_subnet_for_attestation_data::<E>(
        &valid_attestation.data,
        head.beacon_state
            .get_committee_count_at_slot(current_slot)
            .expect("should get committee count"),
        &chain.spec,
    )
    .expect("should get subnet_id");

    (
        valid_attestation,
        validator_index,
        validator_committee_index,
        validator_sk,
        subnet_id,
    )
}

fn get_valid_aggregated_attestation<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    aggregate: Attestation<T::EthSpec>,
) -> (SignedAggregateAndProof<T::EthSpec>, usize, SecretKey) {
    let head = chain.head_snapshot();
    let state = &head.beacon_state;
    let current_slot = chain.slot().expect("should get slot");

    let committee = state
        .get_beacon_committee(current_slot, aggregate.data.index)
        .expect("should get committees");
    let committee_len = committee.committee.len();

    let (aggregator_index, aggregator_sk) = committee
        .committee
        .iter()
        .find_map(|&val_index| {
            let aggregator_sk = generate_deterministic_keypair(val_index).sk;

            let proof = SelectionProof::new::<T::EthSpec>(
                aggregate.data.slot,
                &aggregator_sk,
                &state.fork(),
                chain.genesis_validators_root,
                &chain.spec,
            );

            if proof.is_aggregator(committee_len, &chain.spec).unwrap() {
                Some((val_index, aggregator_sk))
            } else {
                None
            }
        })
        .expect("should find aggregator for committee");

    let signed_aggregate = SignedAggregateAndProof::from_aggregate(
        aggregator_index as u64,
        aggregate,
        None,
        &aggregator_sk,
        &state.fork(),
        chain.genesis_validators_root,
        &chain.spec,
    );

    (signed_aggregate, aggregator_index, aggregator_sk)
}

/// Returns a proof and index for a validator that is **not** an aggregator for the given
/// attestation.
fn get_non_aggregator<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    aggregate: &Attestation<T::EthSpec>,
) -> (usize, SecretKey) {
    let head = chain.head_snapshot();
    let state = &head.beacon_state;
    let current_slot = chain.slot().expect("should get slot");

    let committee = state
        .get_beacon_committee(current_slot, aggregate.data.index)
        .expect("should get committees");
    let committee_len = committee.committee.len();

    committee
        .committee
        .iter()
        .find_map(|&val_index| {
            let aggregator_sk = generate_deterministic_keypair(val_index).sk;

            let proof = SelectionProof::new::<T::EthSpec>(
                aggregate.data.slot,
                &aggregator_sk,
                &state.fork(),
                chain.genesis_validators_root,
                &chain.spec,
            );

            if proof.is_aggregator(committee_len, &chain.spec).unwrap() {
                None
            } else {
                Some((val_index, aggregator_sk))
            }
        })
        .expect("should find non-aggregator for committee")
}

struct GossipTester {
    harness: BeaconChainHarness<EphemeralHarnessType<E>>,
    /*
     * Valid unaggregated attestation
     */
    valid_attestation: Attestation<E>,
    attester_validator_index: usize,
    attester_committee_index: usize,
    attester_sk: SecretKey,
    attestation_subnet_id: SubnetId,
    /*
     * Valid unaggregated attestation for batch testing
     */
    invalid_attestation: Attestation<E>,
    /*
     * Valid aggregate
     */
    valid_aggregate: SignedAggregateAndProof<E>,
    aggregator_validator_index: usize,
    aggregator_sk: SecretKey,
    /*
     * Another valid aggregate for batch testing
     */
    invalid_aggregate: SignedAggregateAndProof<E>,
}

impl GossipTester {
    pub async fn new() -> Self {
        let harness = get_harness(VALIDATOR_COUNT);

        // Extend the chain out a few epochs so we have some chain depth to play with.
        harness
            .extend_chain(
                MainnetEthSpec::slots_per_epoch() as usize * 3 - 1,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::AllValidators,
            )
            .await;

        // Advance into a slot where there have not been blocks or attestations produced.
        harness.advance_slot();

        let (
            valid_attestation,
            attester_validator_index,
            attester_committee_index,
            attester_sk,
            attestation_subnet_id,
        ) = get_valid_unaggregated_attestation(&harness.chain);

        let (valid_aggregate, aggregator_validator_index, aggregator_sk) =
            get_valid_aggregated_attestation(&harness.chain, valid_attestation.clone());

        let mut invalid_attestation = valid_attestation.clone();
        invalid_attestation.data.beacon_block_root = Hash256::repeat_byte(13);

        let (mut invalid_aggregate, _, _) =
            get_valid_aggregated_attestation(&harness.chain, invalid_attestation.clone());
        invalid_aggregate.message.aggregator_index = invalid_aggregate
            .message
            .aggregator_index
            .checked_sub(1)
            .unwrap();

        Self {
            harness,
            valid_attestation,
            attester_validator_index,
            attester_committee_index,
            attester_sk,
            attestation_subnet_id,
            invalid_attestation,
            valid_aggregate,
            aggregator_validator_index,
            aggregator_sk,
            invalid_aggregate,
        }
    }

    pub fn slot(&self) -> Slot {
        self.harness.chain.slot().unwrap()
    }

    pub fn epoch(&self) -> Epoch {
        self.harness.chain.epoch().unwrap()
    }

    pub fn two_epochs_ago(&self) -> Slot {
        self.slot()
            .as_u64()
            .checked_sub(E::slots_per_epoch() + 2)
            .expect("chain is not sufficiently deep for test")
            .into()
    }

    pub fn non_aggregator(&self) -> (usize, SecretKey) {
        get_non_aggregator(&self.harness.chain, &self.valid_aggregate.message.aggregate)
    }

    pub fn import_valid_aggregate(self) -> Self {
        assert!(
            self.harness
                .chain
                .verify_aggregated_attestation_for_gossip(&self.valid_aggregate)
                .is_ok(),
            "valid aggregate should be verified"
        );
        self
    }

    pub fn import_valid_unaggregate(self) -> Self {
        self.harness
            .chain
            .verify_unaggregated_attestation_for_gossip(
                &self.valid_attestation,
                Some(self.attestation_subnet_id),
            )
            .expect("valid attestation should be verified");
        self
    }

    pub fn inspect_aggregate_err<G, I>(self, desc: &str, get_attn: G, inspect_err: I) -> Self
    where
        G: Fn(&Self, &mut SignedAggregateAndProof<E>),
        I: Fn(&Self, AttnError),
    {
        let mut aggregate = self.valid_aggregate.clone();
        get_attn(&self, &mut aggregate);

        /*
         * Individual verification
         */
        let err = self
            .harness
            .chain
            .verify_aggregated_attestation_for_gossip(&aggregate)
            .err()
            .expect(&format!(
                "{} should error during verify_aggregated_attestation_for_gossip",
                desc
            ));
        inspect_err(&self, err);

        /*
         * Batch verification
         */
        let mut results = self
            .harness
            .chain
            .batch_verify_aggregated_attestations_for_gossip(
                vec![&self.invalid_aggregate, &aggregate].into_iter(),
            )
            .unwrap();
        assert_eq!(results.len(), 2);
        let batch_err = results.pop().unwrap().err().expect(&format!(
            "{} should error during batch_verify_aggregated_attestations_for_gossip",
            desc
        ));
        inspect_err(&self, batch_err);

        self
    }

    pub fn inspect_unaggregate_err<G, I>(self, desc: &str, get_attn: G, inspect_err: I) -> Self
    where
        G: Fn(&Self, &mut Attestation<E>, &mut SubnetId),
        I: Fn(&Self, AttnError),
    {
        let mut attn = self.valid_attestation.clone();
        let mut subnet_id = self.attestation_subnet_id;
        get_attn(&self, &mut attn, &mut subnet_id);

        /*
         * Individual verification
         */
        let err = self
            .harness
            .chain
            .verify_unaggregated_attestation_for_gossip(&attn, Some(subnet_id))
            .err()
            .expect(&format!(
                "{} should error during verify_unaggregated_attestation_for_gossip",
                desc
            ));
        inspect_err(&self, err);

        /*
         * Batch verification
         */
        let mut results = self
            .harness
            .chain
            .batch_verify_unaggregated_attestations_for_gossip(
                vec![
                    (&self.invalid_attestation, Some(subnet_id)),
                    (&attn, Some(subnet_id)),
                ]
                .into_iter(),
            )
            .unwrap();
        assert_eq!(results.len(), 2);
        let batch_err = results.pop().unwrap().err().expect(&format!(
            "{} should error during batch_verify_unaggregated_attestations_for_gossip",
            desc
        ));
        inspect_err(&self, batch_err);

        self
    }
}
/// Tests verification of `SignedAggregateAndProof` from the gossip network.
#[tokio::test]
async fn aggregated_gossip_verification() {
    GossipTester::new()
        .await
        /*
         * The following two tests ensure:
         *
         * aggregate.data.slot is within the last ATTESTATION_PROPAGATION_SLOT_RANGE slots (with a
         * MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance) -- i.e. aggregate.data.slot +
         * ATTESTATION_PROPAGATION_SLOT_RANGE >= current_slot >= aggregate.data.slot (a client MAY
         * queue future aggregates for processing at the appropriate slot).
         */
        .inspect_aggregate_err(
            "aggregate from future slot",
            |tester, a| a.message.aggregate.data.slot = tester.slot() + 1,
            |tester, err| {
                assert!(matches!(
                    err,
                    AttnError::FutureSlot { attestation_slot, latest_permissible_slot }
                    if attestation_slot == tester.slot() + 1
                        && latest_permissible_slot == tester.slot()
                ))
            },
        )
        .inspect_aggregate_err(
            "aggregate from past slot",
            |tester, a| a.message.aggregate.data.slot = tester.two_epochs_ago(),
            |tester, err| {
                assert!(matches!(
                    err,
                    AttnError::PastSlot {
                        attestation_slot,
                        // Subtract an additional slot since the harness will be exactly on the start of the
                        // slot and the propagation tolerance will allow an extra slot.
                        earliest_permissible_slot
                    }
                    if attestation_slot == tester.two_epochs_ago()
                        && earliest_permissible_slot == tester.slot() - E::slots_per_epoch() - 1
                ))
            },
        )
        /*
         * The following test ensures:
         *
         * The aggregate attestation's epoch matches its target -- i.e. `aggregate.data.target.epoch ==
         *   compute_epoch_at_slot(attestation.data.slot)`
         *
         */
        .inspect_aggregate_err(
            "attestation with invalid target epoch",
            |_, a| a.message.aggregate.data.target.epoch += 1,
            |_, err| assert!(matches!(err, AttnError::InvalidTargetEpoch { .. })),
        )
        /*
         * This is not in the specification for aggregate attestations (only unaggregates), but we
         * check it anyway to avoid weird edge cases.
         */
        .inspect_aggregate_err(
            "attestation with invalid target root",
            |_, a| a.message.aggregate.data.target.root = Hash256::repeat_byte(42),
            |_, err| assert!(matches!(err, AttnError::InvalidTargetRoot { .. })),
        )
        /*
         * The following test ensures:
         *
         * The block being voted for (aggregate.data.beacon_block_root) passes validation.
         */
        .inspect_aggregate_err(
            "aggregate with unknown head block",
            |_, a| a.message.aggregate.data.beacon_block_root = Hash256::repeat_byte(42),
            |_, err| {
                assert!(matches!(
                    err,
                    AttnError::UnknownHeadBlock {
                        beacon_block_root
                    }
                    if beacon_block_root == Hash256::repeat_byte(42)
                ))
            },
        )
        /*
         * The following test ensures:
         *
         * The attestation has participants.
         */
        .inspect_aggregate_err(
            "aggregate with no participants",
            |_, a| {
                let aggregation_bits = &mut a.message.aggregate.aggregation_bits;
                aggregation_bits.difference_inplace(&aggregation_bits.clone());
                assert!(aggregation_bits.is_zero());
                a.message.aggregate.signature = AggregateSignature::infinity();
            },
            |_, err| assert!(matches!(err, AttnError::EmptyAggregationBitfield)),
        )
        /*
         * This test ensures:
         *
         * The aggregator signature, signed_aggregate_and_proof.signature, is valid.
         */
        .inspect_aggregate_err(
            "aggregate with bad signature",
            |tester, a| a.signature = tester.aggregator_sk.sign(Hash256::repeat_byte(42)),
            |_, err| assert!(matches!(err, AttnError::InvalidSignature)),
        )
        /*
         * The following test ensures:
         *
         * The aggregate_and_proof.selection_proof is a valid signature of the aggregate.data.slot by
         * the validator with index aggregate_and_proof.aggregator_index.
         */
        .inspect_aggregate_err(
            "aggregate with bad signature",
            |tester, a| {
                let committee_len = tester
                    .harness
                    .chain
                    .head_snapshot()
                    .beacon_state
                    .get_beacon_committee(tester.slot(), a.message.aggregate.data.index)
                    .expect("should get committees")
                    .committee
                    .len();

                // Generate some random signature until happens to be a valid selection proof. We need
                // this in order to reach the signature verification code.
                //
                // Could run for ever, but that seems _really_ improbable.
                let mut i: u64 = 0;
                a.message.selection_proof = loop {
                    i += 1;
                    let proof: SelectionProof = tester
                        .aggregator_sk
                        .sign(Hash256::from_slice(&int_to_bytes32(i)))
                        .into();
                    if proof
                        .is_aggregator(committee_len, &tester.harness.chain.spec)
                        .unwrap()
                    {
                        break proof.into();
                    }
                };
            },
            |_, err| assert!(matches!(err, AttnError::InvalidSignature)),
        )
        /*
         * The following test ensures:
         *
         * The signature of aggregate is valid.
         */
        .inspect_aggregate_err(
            "aggregate with bad aggregate signature",
            |tester, a| {
                let mut agg_sig = AggregateSignature::infinity();
                agg_sig.add_assign(&tester.aggregator_sk.sign(Hash256::repeat_byte(42)));
                a.message.aggregate.signature = agg_sig;
            },
            |_, err| assert!(matches!(err, AttnError::InvalidSignature)),
        )
        /*
         * Not directly in the specification, but a sanity check.
         */
        .inspect_aggregate_err(
            "aggregate with too-high aggregator index",
            |_, a| {
                a.message.aggregator_index = <E as EthSpec>::ValidatorRegistryLimit::to_u64() + 1
            },
            |_, err| {
                assert!(matches!(
                    err,
                    AttnError::ValidatorIndexTooHigh(index)
                    if index == (<E as EthSpec>::ValidatorRegistryLimit::to_u64() + 1) as usize
                ))
            },
        )
        /*
         * The following test ensures:
         *
         * The aggregator's validator index is within the committee -- i.e.
         * aggregate_and_proof.aggregator_index in get_beacon_committee(state, aggregate.data.slot,
         * aggregate.data.index).
         */
        .inspect_aggregate_err(
            "aggregate with unknown aggregator index",
            |_, a| a.message.aggregator_index = VALIDATOR_COUNT as u64,
            |_, err| {
                assert!(matches!(
                    err,
                    // Naively we should think this condition would trigger this error:
                    //
                    // AttnError::AggregatorPubkeyUnknown(unknown_validator)
                    //
                    // However the following error is triggered first:
                    AttnError::AggregatorNotInCommittee {
                        aggregator_index
                    }
                    if aggregator_index == VALIDATOR_COUNT as u64
                ))
            },
        )
        /*
         * The following test ensures:
         *
         * aggregate_and_proof.selection_proof selects the validator as an aggregator for the slot --
         * i.e. is_aggregator(state, aggregate.data.slot, aggregate.data.index,
         * aggregate_and_proof.selection_proof) returns True.
         */
        .inspect_aggregate_err(
            "aggregate from non-aggregator",
            |tester, a| {
                let chain = &tester.harness.chain;
                let (index, sk) = tester.non_aggregator();
                *a = SignedAggregateAndProof::from_aggregate(
                    index as u64,
                    tester.valid_aggregate.message.aggregate.clone(),
                    None,
                    &sk,
                    &chain.canonical_head.cached_head().head_fork(),
                    chain.genesis_validators_root,
                    &chain.spec,
                )
            },
            |tester, err| {
                let (val_index, _) = tester.non_aggregator();
                assert!(matches!(
                    err,
                    AttnError::InvalidSelectionProof {
                        aggregator_index: index
                    }
                    if index == val_index as u64
                ))
            },
        )
        // NOTE: from here on, the tests are stateful, and rely on the valid attestation having
        // been seen.
        .import_valid_aggregate()
        /*
         * The following test ensures:
         *
         * The valid aggregate attestation defined by hash_tree_root(aggregate) has not already been
         * seen (via aggregate gossip, within a block, or through the creation of an equivalent
         * aggregate locally).
         */
        .inspect_aggregate_err(
            "aggregate that has already been seen",
            |_, _| {},
            |tester, err| {
                assert!(matches!(
                    err,
                    AttnError::AttestationAlreadyKnown(hash)
                    if hash == tester.valid_aggregate.message.aggregate.tree_hash_root()
                ))
            },
        )
        /*
         * The following test ensures:
         *
         * The aggregate is the first valid aggregate received for the aggregator with index
         * aggregate_and_proof.aggregator_index for the epoch aggregate.data.target.epoch.
         */
        .inspect_aggregate_err(
            "aggregate from aggregator that has already been seen",
            |_, a| a.message.aggregate.data.beacon_block_root = Hash256::repeat_byte(42),
            |tester, err| {
                assert!(matches!(
                    err,
                    AttnError::AggregatorAlreadyKnown(index)
                    if index == tester.aggregator_validator_index as u64
                ))
            },
        );
}

/// Tests the verification conditions for an unaggregated attestation on the gossip network.
#[tokio::test]
async fn unaggregated_gossip_verification() {
    GossipTester::new()
        .await
        /*
         * The following test ensures:
         *
         * The committee index is within the expected range -- i.e. `data.index <
         * get_committee_count_per_slot(state, data.target.epoch)`.
         */
        .inspect_unaggregate_err(
            "attestation with invalid committee index",
            |tester, a, _| {
                a.data.index = tester
                    .harness
                    .chain
                    .head_snapshot()
                    .beacon_state
                    .get_committee_count_at_slot(a.data.slot)
                    .unwrap()
            },
            |_, err| assert!(matches!(err, AttnError::NoCommitteeForSlotAndIndex { .. })),
        )
        /*
         * The following test ensures:
         *
         * The attestation is for the correct subnet (i.e. compute_subnet_for_attestation(state,
         * attestation.data.slot, attestation.data.index) == subnet_id).
         */
        .inspect_unaggregate_err(
            "attestation with invalid committee index",
            |_, _, subnet_id| *subnet_id = SubnetId::new(42),
            |tester, err| {
                assert!(matches!(
                    err,
                    AttnError::InvalidSubnetId {
                        received,
                        expected,
                    }
                    if received == SubnetId::new(42) && expected == tester.attestation_subnet_id
                ))
            },
        )
        /*
         * The following two tests ensure:
         *
         * attestation.data.slot is within the last ATTESTATION_PROPAGATION_SLOT_RANGE slots (within a
         * MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance) -- i.e. attestation.data.slot +
         * ATTESTATION_PROPAGATION_SLOT_RANGE >= current_slot >= attestation.data.slot (a client MAY
         * queue future attestations for processing at the appropriate slot).
         */
        .inspect_unaggregate_err(
            "attestation from future slot",
            |tester, a, _| a.data.slot = tester.slot() + 1,
            |tester, err| {
                assert!(matches!(
                    err,
                    AttnError::FutureSlot {
                        attestation_slot,
                        latest_permissible_slot,
                    }
                    if attestation_slot == tester.slot() + 1 && latest_permissible_slot == tester.slot()
                ))
            },
        )
        .inspect_unaggregate_err(
            "attestation from past slot",
            |tester, a, _| {
                let early_slot = tester.two_epochs_ago();
                a.data.slot = early_slot;
                a.data.target.epoch = early_slot.epoch(E::slots_per_epoch());
            },
            |tester, err| {
                dbg!(&err);
                assert!(matches!(
                    err,
                    AttnError::PastSlot {
                        attestation_slot,
                        // Subtract an additional slot since the harness will be exactly on the start of the
                        // slot and the propagation tolerance will allow an extra slot.
                        earliest_permissible_slot,
                    }
                    if attestation_slot == tester.two_epochs_ago()
                        && earliest_permissible_slot == tester.slot() - E::slots_per_epoch() - 1
                ))
            },
        )
        /*
         * The following test ensures:
         *
         * The attestation's epoch matches its target -- i.e. `attestation.data.target.epoch ==
         *   compute_epoch_at_slot(attestation.data.slot)`
         *
         */
        .inspect_unaggregate_err(
            "attestation with invalid target epoch",
            |_, a, _| a.data.target.epoch += 1,
            |_, err| {
                assert!(matches!(
                    err,
                    AttnError::InvalidTargetEpoch { .. }
                ))
            },
        )
        /*
         * The following two tests ensure:
         *
         * The attestation is unaggregated -- that is, it has exactly one participating validator
         * (len([bit for bit in attestation.aggregation_bits if bit == 0b1]) == 1).
         */
        .inspect_unaggregate_err(
            "attestation without any aggregation bits set",
            |tester, a, _| {
                a.aggregation_bits
                    .set(tester.attester_committee_index, false)
                    .expect("should unset aggregation bit");
                assert_eq!(
                    a.aggregation_bits.num_set_bits(),
                    0,
                    "test requires no set bits"
                );
            },
            |_, err| {
                assert!(matches!(
                    err,
                    AttnError::NotExactlyOneAggregationBitSet(0)
                ))
            },
        )
        .inspect_unaggregate_err(
            "attestation with two aggregation bits set",
            |tester, a, _| {
                a.aggregation_bits
                    .set(tester.attester_committee_index + 1, true)
                    .expect("should set second aggregation bit");
            },
            |_, err| {
                assert!(matches!(
                    err,
                    AttnError::NotExactlyOneAggregationBitSet(2)
                ))
            },
        )
        /*
         * The following test ensures:
         *
         * The number of aggregation bits matches the committee size -- i.e.
         *   `len(attestation.aggregation_bits) == len(get_beacon_committee(state, data.slot,
         *   data.index))`.
         */
        .inspect_unaggregate_err(
            "attestation with invalid bitfield",
            |_, a, _| {
                let bits = a.aggregation_bits.iter().collect::<Vec<_>>();
                a.aggregation_bits = BitList::with_capacity(bits.len() + 1).unwrap();
                for (i, bit) in bits.into_iter().enumerate() {
                    a.aggregation_bits.set(i, bit).unwrap();
                }
            },
            |_, err| {
                assert!(matches!(
                    err,
                    AttnError::Invalid(AttestationValidationError::BeaconStateError(
                        BeaconStateError::InvalidBitfield
                    ))
                ))
            },
        )
        /*
         * The following test ensures that:
         *
         * The block being voted for (attestation.data.beacon_block_root) passes validation.
         */
        .inspect_unaggregate_err(
            "attestation with unknown head block",
            |_, a, _| {
                a.data.beacon_block_root = Hash256::repeat_byte(42);
            },
            |_, err| {
                assert!(matches!(
                    err,
                    AttnError::UnknownHeadBlock {
                        beacon_block_root,
                    }
                    if beacon_block_root == Hash256::repeat_byte(42)
                ))
            },
        )
        /*
         * The following test ensures that:
         *
         * Spec v0.12.3
         *
         * The attestation's target block is an ancestor of the block named in the LMD vote
         */
        .inspect_unaggregate_err(
            "attestation with invalid target root",
            |_, a, _| {
                a.data.target.root = Hash256::repeat_byte(42);
            },
            |_, err| {
                assert!(matches!(
                    err,
                    AttnError::InvalidTargetRoot { .. }
                ))
            },
        )
        /*
         * The following test ensures that:
         *
         * The signature of attestation is valid.
         */
        .inspect_unaggregate_err(
            "attestation with bad signature",
            |tester, a, _| {
                let mut agg_sig = AggregateSignature::infinity();
                agg_sig.add_assign(&tester.attester_sk.sign(Hash256::repeat_byte(42)));
                a.signature = agg_sig;
            },
            |_, err| {
                assert!(matches!(
                    err,
                    AttnError::InvalidSignature
                ))
            },
        )
        // NOTE: from here on, the tests are stateful, and rely on the valid attestation having
        // been seen.
        .import_valid_unaggregate()
        /*
         * The following test ensures that:
         *
         *
         * There has been no other valid attestation seen on an attestation subnet that has an
         * identical attestation.data.target.epoch and participating validator index.
         */
        .inspect_unaggregate_err(
            "attestation that has already been seen",
            |_, _, _| {},
            |tester, err| {
                assert!(matches!(
                    err,
                    AttnError::PriorAttestationKnown {
                        validator_index,
                        epoch,
                    }
                    if validator_index == tester.attester_validator_index as u64 && epoch == tester.epoch()
                ))
            },
        );
}

/// Ensures that an attestation that skips epochs can still be processed.
///
/// This also checks that we can do a state lookup if we don't get a hit from the shuffling cache.
#[tokio::test]
async fn attestation_that_skips_epochs() {
    let harness = get_harness(VALIDATOR_COUNT);

    // Extend the chain out a few epochs so we have some chain depth to play with.
    harness
        .extend_chain(
            MainnetEthSpec::slots_per_epoch() as usize * 3 + 1,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(vec![]),
        )
        .await;

    let current_slot = harness.chain.slot().expect("should get slot");
    let current_epoch = harness.chain.epoch().expect("should get epoch");

    let earlier_slot = (current_epoch - 2).start_slot(MainnetEthSpec::slots_per_epoch());
    let earlier_block = harness
        .chain
        .block_at_slot(earlier_slot, WhenSlotSkipped::Prev)
        .expect("should not error getting block at slot")
        .expect("should find block at slot");

    let mut state = harness
        .chain
        .get_state(&earlier_block.state_root(), Some(earlier_slot))
        .expect("should not error getting state")
        .expect("should find state");

    while state.slot() < current_slot {
        per_slot_processing(&mut state, None, &harness.spec).expect("should process slot");
    }

    let state_root = state.update_tree_hash_cache().unwrap();

    let (attestation, subnet_id) = harness
        .get_unaggregated_attestations(
            &AttestationStrategy::AllValidators,
            &state,
            state_root,
            earlier_block.canonical_root(),
            current_slot,
        )
        .first()
        .expect("should have at least one committee")
        .first()
        .cloned()
        .expect("should have at least one attestation in committee");

    let block_root = attestation.data.beacon_block_root;
    let block_slot = harness
        .chain
        .store
        .get_blinded_block(&block_root)
        .expect("should not error getting block")
        .expect("should find attestation block")
        .message()
        .slot();

    assert!(
        attestation.data.slot - block_slot > E::slots_per_epoch() * 2,
        "the attestation must skip more than two epochs"
    );

    harness
        .chain
        .verify_unaggregated_attestation_for_gossip(&attestation, Some(subnet_id))
        .expect("should gossip verify attestation that skips slots");
}

/// Ensures that an attestation can be processed when a validator receives proposer reward
/// in an epoch _and_ is scheduled for a withdrawal. This is a regression test for a scenario where
/// inconsistent state lookup could cause withdrawal root mismatch.
#[tokio::test]
async fn attestation_validator_receive_proposer_reward_and_withdrawals() {
    let (harness, _) = get_harness_capella_spec(VALIDATOR_COUNT);

    // Advance to a Capella block. Make sure the blocks have attestations.
    let two_thirds = (VALIDATOR_COUNT / 3) * 2;
    let attesters = (0..two_thirds).collect();
    harness
        .extend_chain(
            // To trigger the bug we need the proposer attestation reward to be signed at a block
            // that isn't the first in the epoch.
            MainnetEthSpec::slots_per_epoch() as usize + 1,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(attesters),
        )
        .await;

    // Add BLS change for the block proposer at slot 33. This sets up a withdrawal for the block proposer.
    let proposer_index = harness
        .chain
        .block_at_slot(harness.get_current_slot(), WhenSlotSkipped::None)
        .expect("should not error getting block at slot")
        .expect("should find block at slot")
        .message()
        .proposer_index();
    harness
        .add_bls_to_execution_change(proposer_index, Address::from_low_u64_be(proposer_index))
        .unwrap();

    // Apply two blocks: one to process the BLS change, and another to process the withdrawal.
    harness.advance_slot();
    harness
        .extend_chain(
            2,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(vec![]),
        )
        .await;
    let earlier_slot = harness.get_current_slot();
    let earlier_block = harness
        .chain
        .block_at_slot(earlier_slot, WhenSlotSkipped::None)
        .expect("should not error getting block at slot")
        .expect("should find block at slot");

    // Extend the chain out a few epochs so we have some chain depth to play with.
    harness.advance_slot();
    harness
        .extend_chain(
            MainnetEthSpec::slots_per_epoch() as usize * 2,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(vec![]),
        )
        .await;

    let current_slot = harness.get_current_slot();
    let mut state = harness
        .chain
        .get_state(&earlier_block.state_root(), Some(earlier_slot))
        .expect("should not error getting state")
        .expect("should find state");

    while state.slot() < current_slot {
        per_slot_processing(&mut state, None, &harness.spec).expect("should process slot");
    }

    let state_root = state.update_tree_hash_cache().unwrap();

    // Get an attestation pointed to an old block (where we do not have its shuffling cached).
    // Verifying the attestation triggers an inconsistent state replay.
    let remaining_attesters = (two_thirds..VALIDATOR_COUNT).collect();
    let (attestation, subnet_id) = harness
        .get_unaggregated_attestations(
            &AttestationStrategy::SomeValidators(remaining_attesters),
            &state,
            state_root,
            earlier_block.canonical_root(),
            current_slot,
        )
        .first()
        .expect("should have at least one committee")
        .first()
        .cloned()
        .expect("should have at least one attestation in committee");

    harness
        .chain
        .verify_unaggregated_attestation_for_gossip(&attestation, Some(subnet_id))
        .expect("should gossip verify attestation without checking withdrawals root");
}

#[tokio::test]
async fn attestation_to_finalized_block() {
    let harness = get_harness(VALIDATOR_COUNT);

    // Extend the chain out a few epochs so we have some chain depth to play with.
    harness
        .extend_chain(
            MainnetEthSpec::slots_per_epoch() as usize * 4 + 1,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let finalized_checkpoint = harness
        .chain
        .with_head(|head| Ok::<_, BeaconChainError>(head.beacon_state.finalized_checkpoint()))
        .unwrap();
    assert!(finalized_checkpoint.epoch > 0);

    let current_slot = harness.get_current_slot();

    let earlier_slot = finalized_checkpoint
        .epoch
        .start_slot(MainnetEthSpec::slots_per_epoch())
        - 1;
    let earlier_block = harness
        .chain
        .block_at_slot(earlier_slot, WhenSlotSkipped::Prev)
        .expect("should not error getting block at slot")
        .expect("should find block at slot");
    let earlier_block_root = earlier_block.canonical_root();
    assert_ne!(earlier_block_root, finalized_checkpoint.root);

    let mut state = harness
        .chain
        .get_state(&earlier_block.state_root(), Some(earlier_slot))
        .expect("should not error getting state")
        .expect("should find state");

    while state.slot() < current_slot {
        per_slot_processing(&mut state, None, &harness.spec).expect("should process slot");
    }

    let state_root = state.update_tree_hash_cache().unwrap();

    let (attestation, subnet_id) = harness
        .get_unaggregated_attestations(
            &AttestationStrategy::AllValidators,
            &state,
            state_root,
            earlier_block_root,
            current_slot,
        )
        .first()
        .expect("should have at least one committee")
        .first()
        .cloned()
        .expect("should have at least one attestation in committee");
    assert_eq!(attestation.data.beacon_block_root, earlier_block_root);

    // Attestation should be rejected for attesting to a pre-finalization block.
    let res = harness
        .chain
        .verify_unaggregated_attestation_for_gossip(&attestation, Some(subnet_id));
    assert!(
        matches!(res, Err(AttnError:: HeadBlockFinalized { beacon_block_root })
                      if beacon_block_root == earlier_block_root
        )
    );

    // Pre-finalization block cache should contain the block root.
    assert!(harness
        .chain
        .pre_finalization_block_cache
        .contains(earlier_block_root));
}

#[tokio::test]
async fn verify_aggregate_for_gossip_doppelganger_detection() {
    let harness = get_harness(VALIDATOR_COUNT);

    // Extend the chain out a few epochs so we have some chain depth to play with.
    harness
        .extend_chain(
            MainnetEthSpec::slots_per_epoch() as usize * 3 - 1,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Advance into a slot where there have not been blocks or attestations produced.
    harness.advance_slot();

    let current_slot = harness.chain.slot().expect("should get slot");

    assert_eq!(
        current_slot % E::slots_per_epoch(),
        0,
        "the test requires a new epoch to avoid already-seen errors"
    );

    let (valid_attestation, _attester_index, _attester_committee_index, _, _) =
        get_valid_unaggregated_attestation(&harness.chain);
    let (valid_aggregate, _, _) =
        get_valid_aggregated_attestation(&harness.chain, valid_attestation);

    harness
        .chain
        .verify_aggregated_attestation_for_gossip(&valid_aggregate)
        .expect("should verify aggregate attestation");

    let epoch = valid_aggregate.message.aggregate.data.target.epoch;
    let index = valid_aggregate.message.aggregator_index as usize;
    assert!(harness.chain.validator_seen_at_epoch(index, epoch));

    // Check the correct beacon cache is populated
    assert!(!harness
        .chain
        .observed_block_attesters
        .read()
        .validator_has_been_observed(epoch, index)
        .expect("should check if block attester was observed"));
    assert!(!harness
        .chain
        .observed_gossip_attesters
        .read()
        .validator_has_been_observed(epoch, index)
        .expect("should check if gossip attester was observed"));
    assert!(harness
        .chain
        .observed_aggregators
        .read()
        .validator_has_been_observed(epoch, index)
        .expect("should check if gossip aggregator was observed"));
}

#[tokio::test]
async fn verify_attestation_for_gossip_doppelganger_detection() {
    let harness = get_harness(VALIDATOR_COUNT);

    // Extend the chain out a few epochs so we have some chain depth to play with.
    harness
        .extend_chain(
            MainnetEthSpec::slots_per_epoch() as usize * 3 - 1,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Advance into a slot where there have not been blocks or attestations produced.
    harness.advance_slot();

    let current_slot = harness.chain.slot().expect("should get slot");

    assert_eq!(
        current_slot % E::slots_per_epoch(),
        0,
        "the test requires a new epoch to avoid already-seen errors"
    );

    let (valid_attestation, index, _attester_committee_index, _, subnet_id) =
        get_valid_unaggregated_attestation(&harness.chain);

    harness
        .chain
        .verify_unaggregated_attestation_for_gossip(&valid_attestation, Some(subnet_id))
        .expect("should verify attestation");

    let epoch = valid_attestation.data.target.epoch;
    assert!(harness.chain.validator_seen_at_epoch(index, epoch));

    // Check the correct beacon cache is populated
    assert!(!harness
        .chain
        .observed_block_attesters
        .read()
        .validator_has_been_observed(epoch, index)
        .expect("should check if block attester was observed"));
    assert!(harness
        .chain
        .observed_gossip_attesters
        .read()
        .validator_has_been_observed(epoch, index)
        .expect("should check if gossip attester was observed"));
    assert!(!harness
        .chain
        .observed_aggregators
        .read()
        .validator_has_been_observed(epoch, index)
        .expect("should check if gossip aggregator was observed"));
}

#[tokio::test]
async fn attestation_verification_use_head_state_fork() {
    let (harness, spec) = get_harness_capella_spec(VALIDATOR_COUNT);

    // Advance to last block of the pre-Capella fork epoch. Capella is at slot 32.
    harness
        .extend_chain(
            MainnetEthSpec::slots_per_epoch() as usize * CAPELLA_FORK_EPOCH - 1,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(vec![]),
        )
        .await;

    // Assert our head is a block at slot 31 in the pre-Capella fork epoch.
    let pre_capella_slot = harness.get_current_slot();
    let pre_capella_block = harness
        .chain
        .block_at_slot(pre_capella_slot, WhenSlotSkipped::Prev)
        .expect("should not error getting block at slot")
        .expect("should find block at slot");
    assert_eq!(pre_capella_block.fork_name(&spec).unwrap(), ForkName::Merge);

    // Advance slot clock to Capella fork.
    harness.advance_slot();
    let first_capella_slot = harness.get_current_slot();
    assert_eq!(
        spec.fork_name_at_slot::<E>(first_capella_slot),
        ForkName::Capella
    );

    let (state, state_root) = harness.get_current_state_and_root();

    // Scenario 1: other node signed attestation using the Capella fork epoch.
    {
        let attesters = (0..VALIDATOR_COUNT / 2).collect::<Vec<_>>();
        let capella_fork = spec.fork_for_name(ForkName::Capella).unwrap();
        let committee_attestations = harness
            .make_unaggregated_attestations_with_opts(
                attesters.as_slice(),
                &state,
                state_root,
                pre_capella_block.canonical_root().into(),
                first_capella_slot,
                MakeAttestationOptions {
                    fork: capella_fork,
                    limit: None,
                },
            )
            .0
            .first()
            .cloned()
            .expect("should have at least one committee");
        let attestations_and_subnets = committee_attestations
            .iter()
            .map(|(attestation, subnet_id)| (attestation, Some(*subnet_id)));

        assert!(
            batch_verify_unaggregated_attestations(attestations_and_subnets, &harness.chain).is_ok(),
            "should accept attestations with `data.slot` >= first capella slot signed using the Capella fork"
        );
    }

    // Scenario 2: other node forgot to update their node and signed attestations using bellatrix fork
    {
        let attesters = (VALIDATOR_COUNT / 2..VALIDATOR_COUNT).collect::<Vec<_>>();
        let merge_fork = spec.fork_for_name(ForkName::Merge).unwrap();
        let committee_attestations = harness
            .make_unaggregated_attestations_with_opts(
                attesters.as_slice(),
                &state,
                state_root,
                pre_capella_block.canonical_root().into(),
                first_capella_slot,
                MakeAttestationOptions {
                    fork: merge_fork,
                    limit: None,
                },
            )
            .0
            .first()
            .cloned()
            .expect("should have at least one committee");
        let attestations_and_subnets = committee_attestations
            .iter()
            .map(|(attestation, subnet_id)| (attestation, Some(*subnet_id)));

        let results =
            batch_verify_unaggregated_attestations(attestations_and_subnets, &harness.chain)
                .expect("should return attestation results");
        let error = results
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .err()
            .expect("should return an error");
        assert!(
            matches!(error, Error::InvalidSignature),
            "should reject attestations with `data.slot` >= first capella slot signed using the pre-Capella fork"
        );
    }
}

#[tokio::test]
async fn aggregated_attestation_verification_use_head_state_fork() {
    let (harness, spec) = get_harness_capella_spec(VALIDATOR_COUNT);

    // Advance to last block of the pre-Capella fork epoch. Capella is at slot 32.
    harness
        .extend_chain(
            MainnetEthSpec::slots_per_epoch() as usize * CAPELLA_FORK_EPOCH - 1,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(vec![]),
        )
        .await;

    // Assert our head is a block at slot 31 in the pre-Capella fork epoch.
    let pre_capella_slot = harness.get_current_slot();
    let pre_capella_block = harness
        .chain
        .block_at_slot(pre_capella_slot, WhenSlotSkipped::Prev)
        .expect("should not error getting block at slot")
        .expect("should find block at slot");
    assert_eq!(pre_capella_block.fork_name(&spec).unwrap(), ForkName::Merge);

    // Advance slot clock to Capella fork.
    harness.advance_slot();
    let first_capella_slot = harness.get_current_slot();
    assert_eq!(
        spec.fork_name_at_slot::<E>(first_capella_slot),
        ForkName::Capella
    );

    let (state, state_root) = harness.get_current_state_and_root();

    // Scenario 1: other node signed attestation using the Capella fork epoch.
    {
        let attesters = (0..VALIDATOR_COUNT / 2).collect::<Vec<_>>();
        let capella_fork = spec.fork_for_name(ForkName::Capella).unwrap();
        let aggregates = harness
            .make_attestations_with_opts(
                attesters.as_slice(),
                &state,
                state_root,
                pre_capella_block.canonical_root().into(),
                first_capella_slot,
                MakeAttestationOptions {
                    fork: capella_fork,
                    limit: None,
                },
            )
            .0
            .into_iter()
            .map(|(_, aggregate)| aggregate.expect("should have signed aggregate and proof"))
            .collect::<Vec<_>>();

        assert!(
            batch_verify_aggregated_attestations(aggregates.iter(), &harness.chain).is_ok(),
            "should accept aggregates with `data.slot` >= first capella slot signed using the Capella fork"
        );
    }

    // Scenario 2: other node forgot to update their node and signed attestations using bellatrix fork
    {
        let attesters = (VALIDATOR_COUNT / 2..VALIDATOR_COUNT).collect::<Vec<_>>();
        let merge_fork = spec.fork_for_name(ForkName::Merge).unwrap();
        let aggregates = harness
            .make_attestations_with_opts(
                attesters.as_slice(),
                &state,
                state_root,
                pre_capella_block.canonical_root().into(),
                first_capella_slot,
                MakeAttestationOptions {
                    fork: merge_fork,
                    limit: None,
                },
            )
            .0
            .into_iter()
            .map(|(_, aggregate)| aggregate.expect("should have signed aggregate and proof"))
            .collect::<Vec<_>>();

        let results = batch_verify_aggregated_attestations(aggregates.iter(), &harness.chain)
            .expect("should return attestation results");
        let error = results
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .err()
            .expect("should return an error");
        assert!(
            matches!(error, Error::InvalidSignature),
            "should reject aggregates with `data.slot` >= first capella slot signed using the pre-Capella fork"
        );
    }
}
