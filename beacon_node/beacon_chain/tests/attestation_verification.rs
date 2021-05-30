#![cfg(not(debug_assertions))]

#[macro_use]
extern crate lazy_static;

use beacon_chain::{
    attestation_verification::Error as AttnError,
    test_utils::{AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType},
    BeaconChain, BeaconChainTypes, WhenSlotSkipped,
};
use int_to_bytes::int_to_bytes32;
use state_processing::{
    per_block_processing::errors::AttestationValidationError, per_slot_processing,
};
use store::config::StoreConfig;
use tree_hash::TreeHash;
use types::{
    test_utils::generate_deterministic_keypair, AggregateSignature, Attestation, BeaconStateError,
    BitList, EthSpec, Hash256, Keypair, MainnetEthSpec, SecretKey, SelectionProof,
    SignedAggregateAndProof, SignedBeaconBlock, SubnetId, Unsigned,
};

pub type E = MainnetEthSpec;

/// The validator count needs to be relatively high compared to other tests to ensure that we can
/// have committees where _some_ validators are aggregators but not _all_.
pub const VALIDATOR_COUNT: usize = 256;

lazy_static! {
    /// A cached set of keys.
    static ref KEYPAIRS: Vec<Keypair> = types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT);
}

/// Returns a beacon chain harness.
fn get_harness(validator_count: usize) -> BeaconChainHarness<EphemeralHarnessType<E>> {
    let harness = BeaconChainHarness::new_with_target_aggregators(
        MainnetEthSpec,
        KEYPAIRS[0..validator_count].to_vec(),
        // A kind-of arbitrary number that ensures that _some_ validators are aggregators, but
        // not all.
        4,
        StoreConfig::default(),
    );

    harness.advance_slot();

    harness
}

/// Returns an attestation that is valid for some slot in the given `chain`.
///
/// Also returns some info about who created it.
fn get_valid_unaggregated_attestation<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
) -> (Attestation<T::EthSpec>, usize, usize, SecretKey, SubnetId) {
    let head = chain.head().expect("should get head");
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
            &head.beacon_state.fork,
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
    let state = &chain.head().expect("should get head").beacon_state;
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
                &state.fork,
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
        &state.fork,
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
    let state = &chain.head().expect("should get head").beacon_state;
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
                &state.fork,
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

/// Tests verification of `SignedAggregateAndProof` from the gossip network.
#[test]
fn aggregated_gossip_verification() {
    let harness = get_harness(VALIDATOR_COUNT);

    // Extend the chain out a few epochs so we have some chain depth to play with.
    harness.extend_chain(
        MainnetEthSpec::slots_per_epoch() as usize * 3 - 1,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    // Advance into a slot where there have not been blocks or attestations produced.
    harness.advance_slot();

    let current_slot = harness.chain.slot().expect("should get slot");

    assert_eq!(
        current_slot % E::slots_per_epoch(),
        0,
        "the test requires a new epoch to avoid already-seen errors"
    );

    let (valid_attestation, _attester_index, _attester_committee_index, validator_sk, _subnet_id) =
        get_valid_unaggregated_attestation(&harness.chain);
    let (valid_aggregate, aggregator_index, aggregator_sk) =
        get_valid_aggregated_attestation(&harness.chain, valid_attestation);

    macro_rules! assert_invalid {
        ($desc: tt, $attn_getter: expr, $($error: pat) |+ $( if $guard: expr )?) => {
            assert!(
                matches!(
                    harness
                        .chain
                        .verify_aggregated_attestation_for_gossip($attn_getter)
                        .err()
                        .expect(&format!(
                            "{} should error during verify_aggregated_attestation_for_gossip",
                            $desc
                        )),
                    $( $error ) |+ $( if $guard )?
                ),
                "case: {}",
                $desc,
            );
        };
    }

    /*
     * The following two tests ensure:
     *
     * Spec v0.12.1
     *
     * aggregate.data.slot is within the last ATTESTATION_PROPAGATION_SLOT_RANGE slots (with a
     * MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance) -- i.e. aggregate.data.slot +
     * ATTESTATION_PROPAGATION_SLOT_RANGE >= current_slot >= aggregate.data.slot (a client MAY
     * queue future aggregates for processing at the appropriate slot).
     */

    let future_slot = current_slot + 1;
    assert_invalid!(
        "aggregate from future slot",
        {
            let mut a = valid_aggregate.clone();
            a.message.aggregate.data.slot = future_slot;
            a
        },
        AttnError::FutureSlot { attestation_slot, latest_permissible_slot }
        if attestation_slot == future_slot && latest_permissible_slot == current_slot
    );

    let early_slot = current_slot
        .as_u64()
        .checked_sub(E::slots_per_epoch() + 2)
        .expect("chain is not sufficiently deep for test")
        .into();
    assert_invalid!(
        "aggregate from past slot",
        {
            let mut a = valid_aggregate.clone();
            a.message.aggregate.data.slot = early_slot;
            a
        },
        AttnError::PastSlot {
            attestation_slot,
            // Subtract an additional slot since the harness will be exactly on the start of the
            // slot and the propagation tolerance will allow an extra slot.
            earliest_permissible_slot
        }
        if attestation_slot == early_slot
            && earliest_permissible_slot == current_slot - E::slots_per_epoch() - 1
    );

    /*
     * The following test ensures:
     *
     * The aggregate attestation's epoch matches its target -- i.e. `aggregate.data.target.epoch ==
     *   compute_epoch_at_slot(attestation.data.slot)`
     *
     */

    assert_invalid!(
        "attestation with invalid target epoch",
        {
            let mut a = valid_aggregate.clone();
            a.message.aggregate.data.target.epoch += 1;
            a
        },
        AttnError::InvalidTargetEpoch { .. }
    );
    /*
     * This is not in the specification for aggregate attestations (only unaggregates), but we
     * check it anyway to avoid weird edge cases.
     */
    let unknown_root = Hash256::from_low_u64_le(424242);
    assert_invalid!(
        "attestation with invalid target root",
        {
            let mut a = valid_aggregate.clone();
            a.message.aggregate.data.target.root = unknown_root;
            a
        },
        AttnError::InvalidTargetRoot { .. }
    );

    /*
     * The following test ensures:
     *
     * Spec v0.12.1
     *
     * The block being voted for (aggregate.data.beacon_block_root) passes validation.
     */

    let unknown_root = Hash256::from_low_u64_le(424242);
    assert_invalid!(
        "aggregate with unknown head block",
        {
            let mut a = valid_aggregate.clone();
            a.message.aggregate.data.beacon_block_root = unknown_root;
            a
        },
        AttnError::UnknownHeadBlock {
            beacon_block_root
        }
        if beacon_block_root == unknown_root
    );

    /*
     * The following test ensures:
     *
     * Spec v0.12.1
     *
     * The attestation has participants.
     */

    assert_invalid!(
        "aggregate with no participants",
        {
            let mut a = valid_aggregate.clone();
            let aggregation_bits = &mut a.message.aggregate.aggregation_bits;
            aggregation_bits.difference_inplace(&aggregation_bits.clone());
            assert!(aggregation_bits.is_zero());
            a.message.aggregate.signature = AggregateSignature::infinity();
            a
        },
        AttnError::EmptyAggregationBitfield
    );

    /*
     * This test ensures:
     *
     * Spec v0.12.1
     *
     * The aggregator signature, signed_aggregate_and_proof.signature, is valid.
     */

    assert_invalid!(
        "aggregate with bad signature",
        {
            let mut a = valid_aggregate.clone();

            a.signature = validator_sk.sign(Hash256::from_low_u64_be(42));

            a
        },
        AttnError::InvalidSignature
    );

    /*
     * The following test ensures:
     *
     * Spec v0.12.1
     *
     * The aggregate_and_proof.selection_proof is a valid signature of the aggregate.data.slot by
     * the validator with index aggregate_and_proof.aggregator_index.
     */

    let committee_len = harness
        .chain
        .head()
        .unwrap()
        .beacon_state
        .get_beacon_committee(
            harness.chain.slot().unwrap(),
            valid_aggregate.message.aggregate.data.index,
        )
        .expect("should get committees")
        .committee
        .len();
    assert_invalid!(
        "aggregate with bad selection proof signature",
        {
            let mut a = valid_aggregate.clone();

            // Generate some random signature until happens to be a valid selection proof. We need
            // this in order to reach the signature verification code.
            //
            // Could run for ever, but that seems _really_ improbable.
            let mut i: u64 = 0;
            a.message.selection_proof = loop {
                i += 1;
                let proof: SelectionProof = validator_sk
                    .sign(Hash256::from_slice(&int_to_bytes32(i)))
                    .into();
                if proof
                    .is_aggregator(committee_len, &harness.chain.spec)
                    .unwrap()
                {
                    break proof.into();
                }
            };

            a
        },
        AttnError::InvalidSignature
    );

    /*
     * The following test ensures:
     *
     * Spec v0.12.1
     *
     * The signature of aggregate is valid.
     */

    assert_invalid!(
        "aggregate with bad aggregate signature",
        {
            let mut a = valid_aggregate.clone();

            let mut agg_sig = AggregateSignature::infinity();
            agg_sig.add_assign(&aggregator_sk.sign(Hash256::from_low_u64_be(42)));
            a.message.aggregate.signature = agg_sig;

            a
        },
        AttnError::InvalidSignature
    );

    let too_high_index = <E as EthSpec>::ValidatorRegistryLimit::to_u64() + 1;
    assert_invalid!(
        "aggregate with too-high aggregator index",
        {
            let mut a = valid_aggregate.clone();
            a.message.aggregator_index = too_high_index;
            a
        },
        AttnError::ValidatorIndexTooHigh(index)
        if index == too_high_index as usize
    );

    /*
     * The following test ensures:
     *
     * Spec v0.12.1
     *
     * The aggregator's validator index is within the committee -- i.e.
     * aggregate_and_proof.aggregator_index in get_beacon_committee(state, aggregate.data.slot,
     * aggregate.data.index).
     */

    let unknown_validator = VALIDATOR_COUNT as u64;
    assert_invalid!(
        "aggregate with unknown aggregator index",
        {
            let mut a = valid_aggregate.clone();
            a.message.aggregator_index = unknown_validator;
            a
        },
        // Naively we should think this condition would trigger this error:
        //
        // AttnError::AggregatorPubkeyUnknown(unknown_validator)
        //
        // However the following error is triggered first:
        AttnError::AggregatorNotInCommittee {
            aggregator_index
        }
        if aggregator_index == unknown_validator
    );

    /*
     * The following test ensures:
     *
     * Spec v0.12.1
     *
     * aggregate_and_proof.selection_proof selects the validator as an aggregator for the slot --
     * i.e. is_aggregator(state, aggregate.data.slot, aggregate.data.index,
     * aggregate_and_proof.selection_proof) returns True.
     */

    let (non_aggregator_index, non_aggregator_sk) =
        get_non_aggregator(&harness.chain, &valid_aggregate.message.aggregate);
    assert_invalid!(
        "aggregate from non-aggregator",
        {
            SignedAggregateAndProof::from_aggregate(
                non_aggregator_index as u64,
                valid_aggregate.message.aggregate.clone(),
                None,
                &non_aggregator_sk,
                &harness.chain.head_info().unwrap().fork,
                harness.chain.genesis_validators_root,
                &harness.chain.spec,
            )
        },
        AttnError::InvalidSelectionProof {
            aggregator_index: index
        }
        if index == non_aggregator_index as u64
    );

    // NOTE: from here on, the tests are stateful, and rely on the valid attestation having been
    // seen. A refactor to give each test case its own state might be nice at some point
    assert!(
        harness
            .chain
            .verify_aggregated_attestation_for_gossip(valid_aggregate.clone())
            .is_ok(),
        "valid aggregate should be verified"
    );

    /*
     * The following test ensures:
     *
     * Spec v0.12.1
     *
     * The valid aggregate attestation defined by hash_tree_root(aggregate) has not already been
     * seen (via aggregate gossip, within a block, or through the creation of an equivalent
     * aggregate locally).
     */

    assert_invalid!(
        "aggregate that has already been seen",
        valid_aggregate.clone(),
        AttnError::AttestationAlreadyKnown(hash)
        if hash == valid_aggregate.message.aggregate.tree_hash_root()
    );

    /*
     * The following test ensures:
     *
     * Spec v0.12.1
     *
     * The aggregate is the first valid aggregate received for the aggregator with index
     * aggregate_and_proof.aggregator_index for the epoch aggregate.data.target.epoch.
     */

    assert_invalid!(
        "aggregate from aggregator that has already been seen",
        {
            let mut a = valid_aggregate.clone();
            a.message.aggregate.data.beacon_block_root = Hash256::from_low_u64_le(42);
            a
        },
        AttnError::AggregatorAlreadyKnown(index)
        if index == aggregator_index as u64
    );
}

/// Tests the verification conditions for an unaggregated attestation on the gossip network.
#[test]
fn unaggregated_gossip_verification() {
    let harness = get_harness(VALIDATOR_COUNT);

    // Extend the chain out a few epochs so we have some chain depth to play with.
    harness.extend_chain(
        MainnetEthSpec::slots_per_epoch() as usize * 3 - 1,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    // Advance into a slot where there have not been blocks or attestations produced.
    harness.advance_slot();

    let current_slot = harness.chain.slot().expect("should get slot");
    let current_epoch = harness.chain.epoch().expect("should get epoch");

    assert_eq!(
        current_slot % E::slots_per_epoch(),
        0,
        "the test requires a new epoch to avoid already-seen errors"
    );

    let (
        valid_attestation,
        expected_validator_index,
        validator_committee_index,
        validator_sk,
        subnet_id,
    ) = get_valid_unaggregated_attestation(&harness.chain);

    macro_rules! assert_invalid {
        ($desc: tt, $attn_getter: expr, $subnet_getter: expr, $($error: pat) |+ $( if $guard: expr )?) => {
            assert!(
                matches!(
                    harness
                        .chain
                        .verify_unaggregated_attestation_for_gossip($attn_getter, Some($subnet_getter))
                        .err()
                        .expect(&format!(
                            "{} should error during verify_unaggregated_attestation_for_gossip",
                            $desc
                        )),
                    $( $error ) |+ $( if $guard )?
                ),
                "case: {}",
                $desc,
            );
        };
    }

    /*
     * The following test ensures:
     *
     * Spec v0.12.3
     *
     * The committee index is within the expected range -- i.e. `data.index <
     * get_committee_count_per_slot(state, data.target.epoch)`.
     */
    assert_invalid!(
        "attestation with invalid committee index",
        {
            let mut a = valid_attestation.clone();
            a.data.index = harness
                .chain
                .head()
                .unwrap()
                .beacon_state
                .get_committee_count_at_slot(a.data.slot)
                .unwrap();
            a
        },
        subnet_id,
        AttnError::NoCommitteeForSlotAndIndex { .. }
    );

    /*
     * The following test ensures:
     *
     * Spec v0.12.1
     *
     * The attestation is for the correct subnet (i.e. compute_subnet_for_attestation(state,
     * attestation.data.slot, attestation.data.index) == subnet_id).
     */
    let id: u64 = subnet_id.into();
    let invalid_subnet_id = SubnetId::new(id + 1);
    assert_invalid!(
        "attestation from future slot",
        {
            valid_attestation.clone()
        },
        invalid_subnet_id,
        AttnError::InvalidSubnetId {
            received,
            expected,
        }
        if received == invalid_subnet_id && expected == subnet_id
    );

    /*
     * The following two tests ensure:
     *
     * Spec v0.12.1
     *
     * attestation.data.slot is within the last ATTESTATION_PROPAGATION_SLOT_RANGE slots (within a
     * MAXIMUM_GOSSIP_CLOCK_DISPARITY allowance) -- i.e. attestation.data.slot +
     * ATTESTATION_PROPAGATION_SLOT_RANGE >= current_slot >= attestation.data.slot (a client MAY
     * queue future attestations for processing at the appropriate slot).
     */

    let future_slot = current_slot + 1;
    assert_invalid!(
        "attestation from future slot",
        {
            let mut a = valid_attestation.clone();
            a.data.slot = future_slot;
            a
        },
        subnet_id,
        AttnError::FutureSlot {
            attestation_slot,
            latest_permissible_slot,
        }
        if attestation_slot == future_slot && latest_permissible_slot == current_slot
    );

    let early_slot = current_slot
        .as_u64()
        .checked_sub(E::slots_per_epoch() + 2)
        .expect("chain is not sufficiently deep for test")
        .into();
    assert_invalid!(
        "attestation from past slot",
        {
            let mut a = valid_attestation.clone();
            a.data.slot = early_slot;
            a.data.target.epoch = early_slot.epoch(E::slots_per_epoch());
            a
        },
        subnet_id,
        AttnError::PastSlot {
            attestation_slot,
            // Subtract an additional slot since the harness will be exactly on the start of the
            // slot and the propagation tolerance will allow an extra slot.
            earliest_permissible_slot,
        }
        if attestation_slot == early_slot && earliest_permissible_slot == current_slot - E::slots_per_epoch() - 1
    );

    /*
     * The following test ensures:
     *
     * Spec v0.12.3
     *
     * The attestation's epoch matches its target -- i.e. `attestation.data.target.epoch ==
     *   compute_epoch_at_slot(attestation.data.slot)`
     *
     */

    assert_invalid!(
        "attestation with invalid target epoch",
        {
            let mut a = valid_attestation.clone();
            a.data.target.epoch += 1;
            a
        },
        subnet_id,
        AttnError::InvalidTargetEpoch { .. }
    );

    /*
     * The following two tests ensure:
     *
     * Spec v0.12.1
     *
     * The attestation is unaggregated -- that is, it has exactly one participating validator
     * (len([bit for bit in attestation.aggregation_bits if bit == 0b1]) == 1).
     */

    assert_invalid!(
        "attestation without any aggregation bits set",
        {
            let mut a = valid_attestation.clone();
            a.aggregation_bits
                .set(validator_committee_index, false)
                .expect("should unset aggregation bit");
            assert_eq!(
                a.aggregation_bits.num_set_bits(),
                0,
                "test requires no set bits"
            );
            a
        },
        subnet_id,
        AttnError::NotExactlyOneAggregationBitSet(0)
    );

    assert_invalid!(
        "attestation with two aggregation bits set",
        {
            let mut a = valid_attestation.clone();
            a.aggregation_bits
                .set(validator_committee_index + 1, true)
                .expect("should set second aggregation bit");
            a
        },
        subnet_id,
        AttnError::NotExactlyOneAggregationBitSet(2)
    );

    /*
     * The following test ensures:
     *
     * Spec v0.12.3
     *
     * The number of aggregation bits matches the committee size -- i.e.
     *   `len(attestation.aggregation_bits) == len(get_beacon_committee(state, data.slot,
     *   data.index))`.
     */
    assert_invalid!(
        "attestation with invalid bitfield",
        {
            let mut a = valid_attestation.clone();
            let bits = a.aggregation_bits.iter().collect::<Vec<_>>();
            a.aggregation_bits = BitList::with_capacity(bits.len() + 1).unwrap();
            for (i, bit) in bits.into_iter().enumerate() {
                a.aggregation_bits.set(i, bit).unwrap();
            }
            a
        },
        subnet_id,
        AttnError::Invalid(AttestationValidationError::BeaconStateError(
            BeaconStateError::InvalidBitfield
        ))
    );

    /*
     * The following test ensures that:
     *
     * Spec v0.12.1
     *
     * The block being voted for (attestation.data.beacon_block_root) passes validation.
     */

    let unknown_root = Hash256::from_low_u64_le(424242); // No one wants one of these
    assert_invalid!(
        "attestation with unknown head block",
        {
            let mut a = valid_attestation.clone();
            a.data.beacon_block_root = unknown_root;
            a
        },
        subnet_id,
        AttnError::UnknownHeadBlock {
            beacon_block_root,
        }
        if beacon_block_root == unknown_root
    );

    /*
     * The following test ensures that:
     *
     * Spec v0.12.3
     *
     * The attestation's target block is an ancestor of the block named in the LMD vote
     */

    let unknown_root = Hash256::from_low_u64_le(424242);
    assert_invalid!(
        "attestation with invalid target root",
        {
            let mut a = valid_attestation.clone();
            a.data.target.root = unknown_root;
            a
        },
        subnet_id,
        AttnError::InvalidTargetRoot { .. }
    );

    /*
     * The following test ensures that:
     *
     * Spec v0.12.1
     *
     * The signature of attestation is valid.
     */

    assert_invalid!(
        "attestation with bad signature",
        {
            let mut a = valid_attestation.clone();

            let mut agg_sig = AggregateSignature::infinity();
            agg_sig.add_assign(&validator_sk.sign(Hash256::from_low_u64_be(42)));
            a.signature = agg_sig;

            a
        },
        subnet_id,
        AttnError::InvalidSignature
    );

    harness
        .chain
        .verify_unaggregated_attestation_for_gossip(valid_attestation.clone(), Some(subnet_id))
        .expect("valid attestation should be verified");

    /*
     * The following test ensures that:
     *
     * Spec v0.12.1
     *
     *
     * There has been no other valid attestation seen on an attestation subnet that has an
     * identical attestation.data.target.epoch and participating validator index.
     */

    assert_invalid!(
        "attestation that has already been seen",
        valid_attestation.clone(),
        subnet_id,
        AttnError::PriorAttestationKnown {
            validator_index,
            epoch,
        }
        if validator_index == expected_validator_index as u64 && epoch == current_epoch
    );
}

/// Ensures that an attestation that skips epochs can still be processed.
///
/// This also checks that we can do a state lookup if we don't get a hit from the shuffling cache.
#[test]
fn attestation_that_skips_epochs() {
    let harness = get_harness(VALIDATOR_COUNT);

    // Extend the chain out a few epochs so we have some chain depth to play with.
    harness.extend_chain(
        MainnetEthSpec::slots_per_epoch() as usize * 3 + 1,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::SomeValidators(vec![]),
    );

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

    while state.slot < current_slot {
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
        .get_item::<SignedBeaconBlock<E>>(&block_root)
        .expect("should not error getting block")
        .expect("should find attestation block")
        .message
        .slot;

    assert!(
        attestation.data.slot - block_slot > E::slots_per_epoch() * 2,
        "the attestation must skip more than two epochs"
    );

    harness
        .chain
        .verify_unaggregated_attestation_for_gossip(attestation, Some(subnet_id))
        .expect("should gossip verify attestation that skips slots");
}
