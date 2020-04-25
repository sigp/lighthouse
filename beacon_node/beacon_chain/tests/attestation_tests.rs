// #![cfg(not(debug_assertions))]

#[macro_use]
extern crate lazy_static;

use beacon_chain::AttestationProcessingOutcome;
use beacon_chain::{
    attestation_verification::{Error as AttnError, VerifiedUnaggregatedAttestation},
    test_utils::{AttestationStrategy, BeaconChainHarness, BlockStrategy, HarnessType},
    BeaconChain, BeaconChainTypes,
};
use state_processing::per_slot_processing;
use tree_hash::TreeHash;
use types::{
    test_utils::generate_deterministic_keypair, AggregateSignature, Attestation, BitList, EthSpec,
    Hash256, Keypair, MainnetEthSpec, SecretKey, SelectionProof, Signature,
    SignedAggregateAndProof, Slot, Unsigned,
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
fn get_harness(validator_count: usize) -> BeaconChainHarness<HarnessType<E>> {
    let harness = BeaconChainHarness::new_with_target_aggregators(
        MainnetEthSpec,
        KEYPAIRS[0..validator_count].to_vec(),
        // A kind-of arbitrary number that ensures that _some_ validators are aggregators, but
        // not all.
        4,
    );

    harness.advance_slot();

    harness
}

/// Returns an attestation that is valid for some slot in the given `chain`.
///
/// Also returns some info about who created it.
fn get_valid_unaggregated_attestation<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
) -> (Attestation<T::EthSpec>, usize, usize, SecretKey) {
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

    (
        valid_attestation,
        validator_index,
        validator_committee_index,
        validator_sk,
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
    let chain = &harness.chain;

    // Extend the chain out a few epochs so we have some chain depth to play with.
    harness.extend_chain(
        MainnetEthSpec::slots_per_epoch() as usize * 3 - 1,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    // Advance into a slot where there have not been blocks or attestations produced.
    harness.advance_slot();

    let current_slot = chain.slot().expect("should get slot");

    assert_eq!(
        current_slot % E::slots_per_epoch(),
        0,
        "the test requires a new epoch to avoid already-seen errors"
    );

    let (valid_attestation, _attester_index, _attester_committee_index, validator_sk) =
        get_valid_unaggregated_attestation(&harness.chain);
    let (valid_aggregate, aggregator_index, aggregator_sk) =
        get_valid_aggregated_attestation(&harness.chain, valid_attestation);

    macro_rules! assert_invalid {
        ($desc: tt, $attn_getter: expr, $error: expr) => {
            assert_eq!(
                harness
                    .chain
                    .verify_aggregated_attestation_for_gossip($attn_getter)
                    .err()
                    .expect(&format!(
                        "{} should error during VerifiedUnaggregatedAttestation::verify",
                        $desc
                    )),
                $error,
                "case: {}",
                $desc,
            );
        };
    }

    /*
     * The following two tests ensure:
     *
     * Spec v0.11.1
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
        AttnError::FutureSlot {
            attestation_slot: future_slot,
            latest_permissible_slot: current_slot,
        }
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
            attestation_slot: early_slot,
            // Subtract an additional slot since the harness will be exactly on the start of the
            // slot and the propagation tolerance will allow an extra slot.
            earliest_permissible_slot: current_slot - E::slots_per_epoch() - 1,
        }
    );

    /*
     * The following test ensures:
     *
     * Spec v0.11.1
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
            beacon_block_root: unknown_root
        }
    );

    /*
     * This test ensures:
     *
     * Spec v0.11.1
     *
     * The aggregator signature, signed_aggregate_and_proof.signature, is valid.
     */

    assert_invalid!(
        "aggregate with bad signature",
        {
            let mut a = valid_aggregate.clone();

            a.signature = Signature::new(&[42, 42], &validator_sk);

            a
        },
        AttnError::InvalidSignature
    );

    /*
     * The following test ensures:
     *
     * Spec v0.11.1
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
                let proof: SelectionProof = Signature::new(&i.to_le_bytes(), &validator_sk).into();
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
     * Spec v0.11.1
     *
     * The signature of aggregate is valid.
     */

    assert_invalid!(
        "aggregate with bad aggregate signature",
        {
            let mut a = valid_aggregate.clone();

            let mut agg_sig = AggregateSignature::new();
            agg_sig.add(&Signature::new(&[42, 42], &aggregator_sk));
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
        AttnError::ValidatorIndexTooHigh(too_high_index as usize)
    );

    /*
     * The following test ensures:
     *
     * Spec v0.11.1
     *
     * The aggregator's validator index is within the aggregate's committee -- i.e.
     * aggregate_and_proof.aggregator_index in get_attesting_indices(state, aggregate.data,
     * aggregate.aggregation_bits).
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
            aggregator_index: unknown_validator
        }
    );

    /*
     * The following test ensures:
     *
     * Spec v0.11.1
     *
     * aggregate_and_proof.selection_proof selects the validator as an aggregator for the slot --
     * i.e. is_aggregator(state, aggregate.data.slot, aggregate.data.index,
     * aggregate_and_proof.selection_proof) returns True.
     */

    let (non_aggregator_index, non_aggregator_sk) =
        get_non_aggregator(&harness.chain, &valid_aggregate.message.aggregate);
    assert_invalid!(
        "aggregate with from non-aggregator",
        {
            SignedAggregateAndProof::from_aggregate(
                non_aggregator_index as u64,
                valid_aggregate.message.aggregate.clone(),
                &non_aggregator_sk,
                &harness.chain.head_info().unwrap().fork,
                harness.chain.genesis_validators_root,
                &harness.chain.spec,
            )
        },
        AttnError::InvalidSelectionProof {
            aggregator_index: non_aggregator_index as u64
        }
    );

    assert!(
        harness
            .chain
            .verify_aggregated_attestation_for_gossip(valid_aggregate.clone())
            .is_ok(),
        "valid aggregate should be verified"
    );

    /*
     * The following tests ensures:
     *
     * NOTE: this is technically not part of the spec, see:
     * https://github.com/ethereum/eth2.0-specs/pull/1749
     *
     * Spec v0.11.1
     *
     * The aggregate attestation defined by hash_tree_root(aggregate) has not already been seen
     * (via aggregate gossip, within a block, or through the creation of an equivalent aggregate
     * locally).
     */

    assert_invalid!(
        "aggregate with that has already been seen",
        valid_aggregate.clone(),
        AttnError::AttestationAlreadyKnown(valid_aggregate.message.aggregate.tree_hash_root())
    );

    /*
     * The following test ensures:
     *
     * Spec v0.11.1
     *
     * The aggregate is the first valid aggregate received for the aggregator with index
     * aggregate_and_proof.aggregator_index for the slot aggregate.data.slot.
     */

    assert_invalid!(
        "aggregate from aggregator that has already been seen",
        {
            let mut a = valid_aggregate.clone();
            a.message.aggregate.data.beacon_block_root = Hash256::from_low_u64_le(42);
            a
        },
        AttnError::AggregatorAlreadyKnown(aggregator_index as u64)
    );
}

/// Tests the verification conditions for an unaggregated attestation on the gossip network.
#[test]
fn unaggregated_gossip_verification() {
    let harness = get_harness(VALIDATOR_COUNT);
    let chain = &harness.chain;

    // Extend the chain out a few epochs so we have some chain depth to play with.
    harness.extend_chain(
        MainnetEthSpec::slots_per_epoch() as usize * 3 - 1,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    // Advance into a slot where there have not been blocks or attestations produced.
    harness.advance_slot();

    let current_slot = chain.slot().expect("should get slot");
    let current_epoch = chain.epoch().expect("should get epoch");

    assert_eq!(
        current_slot % E::slots_per_epoch(),
        0,
        "the test requires a new epoch to avoid already-seen errors"
    );

    let (valid_attestation, validator_index, validator_committee_index, validator_sk) =
        get_valid_unaggregated_attestation(&harness.chain);

    macro_rules! assert_invalid {
        ($desc: tt, $attn_getter: expr, $error: expr) => {
            assert_eq!(
                harness
                    .chain
                    .verify_unaggregated_attestation_for_gossip($attn_getter)
                    .err()
                    .expect(&format!(
                        "{} should error during VerifiedUnaggregatedAttestation::verify",
                        $desc
                    )),
                $error,
                "case: {}",
                $desc,
            );
        };
    }

    /*
     * The following two tests ensure:
     *
     * Spec v0.11.1
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
        AttnError::FutureSlot {
            attestation_slot: future_slot,
            latest_permissible_slot: current_slot,
        }
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
            a
        },
        AttnError::PastSlot {
            attestation_slot: early_slot,
            // Subtract an additional slot since the harness will be exactly on the start of the
            // slot and the propagation tolerance will allow an extra slot.
            earliest_permissible_slot: current_slot - E::slots_per_epoch() - 1,
        }
    );

    /*
     * The following two tests ensure:
     *
     * Spec v0.11.1
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
        AttnError::NotExactlyOneAggregationBitSet(2)
    );

    /*
     * The following test ensures that:
     *
     * Spec v0.11.1
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
        AttnError::UnknownHeadBlock {
            beacon_block_root: unknown_root
        }
    );

    /*
     * The following test ensures that:
     *
     * Spec v0.11.1
     *
     * The signature of attestation is valid.
     */

    assert_invalid!(
        "attestation with bad signature",
        {
            let mut a = valid_attestation.clone();

            let mut agg_sig = AggregateSignature::new();
            agg_sig.add(&Signature::new(&[42, 42], &validator_sk));
            a.signature = agg_sig;

            a
        },
        AttnError::InvalidSignature
    );

    assert!(
        harness
            .chain
            .verify_unaggregated_attestation_for_gossip(valid_attestation.clone())
            .is_ok(),
        "valid attestation should be verified"
    );

    /*
     * The following test ensures that:
     *
     * Spec v0.11.1
     *
     * The attestation is the first valid attestation received for the participating validator for
     * the slot, attestation.data.slot.
     */

    assert_invalid!(
        "attestation that has already been seen",
        valid_attestation.clone(),
        AttnError::PriorAttestationKnown {
            validator_index: validator_index as u64,
            epoch: current_epoch
        }
    );
}

/*
 * TODO: finish this
 *
#[test]
fn attestation_that_skips_epochs() {
    let harness = get_harness(VALIDATOR_COUNT);
    let chain = &harness.chain;

    // Extend the chain out a few epochs so we have some chain depth to play with.
    harness.extend_chain(
        MainnetEthSpec::slots_per_epoch() as usize * 3 + 1,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    let current_slot = chain.slot().expect("should get slot");
    let current_epoch = chain.epoch().expect("should get epoch");

    let earlier_slot = (current_epoch - 2).start_slot(MainnetEthSpec::slots_per_epoch());
    let earlier_block = chain
        .block_at_slot(earlier_slot)
        .expect("should not error getting block at slot")
        .expect("should find block at slot");

    let mut state = chain
        .get_state(&earlier_block.state_root(), Some(earlier_slot))
        .expect("should not error getting state")
        .expect("should find state");

    while state.slot < current_slot {
        per_slot_processing(&mut state, None, &harness.spec).expect("should process slot");
    }

    let (valid_attestation, _attester_index, _attester_committee_index, validator_sk) =
        get_valid_unaggregated_attestation(&harness.chain);

    let attestation = harness
        .get_unaggregated_attestations(
            &AttestationStrategy::AllValidators,
            &state,
            earlier_block.canonical_root(),
            current_slot,
        )
        .first()
        .expect("should have at least one committee")
        .first()
        .cloned()
        .expect("should have at least one attestation in committee");

    assert_eq!(
        harness.chain.process_attestation(attestation),
        Ok(AttestationProcessingOutcome::Processed),
        "should process attestation that skips slots"
    );
}
*/

/*
assert_invalid(
    &harness,
    || invalidate_as_future_slot(valid_attestation.clone(), current_slot),
    AttnError::FutureSlot {
        attestation_slot: current_slot + 1,
        latest_permissible_slot: current_slot,
    },
    "future slot",
);

assert_eq!(
    try_verify(&harness, || invalidate_as_future_slot(
        valid_attestation.clone(),
        current_slot
    ))
    .err()
    .expect("should error"),
    AttnError::FutureSlot {
        attestation_slot: current_slot + 1,
        latest_permissible_slot: current_slot
    },
    "should refuse future slot"
);
*/

/*
assert_eq!(
    chain.process_attestation(valid_attestation.clone()),
    Ok(AttestationProcessingOutcome::Processed),
    "should accept valid attestation"
);

/*
 * Should reject attestations if the slot does not match the target epoch.
 */

let mut epoch_mismatch_attestation = valid_attestation.clone();
epoch_mismatch_attestation.data.target.epoch = current_epoch + 1;

assert_eq!(
    harness
        .chain
        .process_attestation(epoch_mismatch_attestation),
    Ok(AttestationProcessingOutcome::BadTargetEpoch),
    "should not accept attestation where the slot is not in the same epoch as the target"
);

/*
 * Should reject attestations from future epochs.
 */

let mut early_attestation = valid_attestation.clone();
early_attestation.data.target.epoch = current_epoch + 1;
early_attestation.data.slot = (current_epoch + 1).start_slot(MainnetEthSpec::slots_per_epoch());

assert_eq!(
    harness.chain.process_attestation(early_attestation),
    Ok(AttestationProcessingOutcome::FutureEpoch {
        attestation_epoch: current_epoch + 1,
        current_epoch
    }),
    "should not accept early attestation"
);

/*
 * Should reject attestations from epochs prior to the previous epoch.
 */

let late_slot = (current_epoch - 2).start_slot(MainnetEthSpec::slots_per_epoch());
let late_block = chain
    .block_at_slot(late_slot)
    .expect("should not error getting block at slot")
    .expect("should find block at slot");
let late_state = chain
    .get_state(&late_block.state_root(), Some(late_slot))
    .expect("should not error getting state")
    .expect("should find state");
let late_attestation = harness
    .get_unaggregated_attestations(
        &AttestationStrategy::AllValidators,
        &late_state,
        late_block.canonical_root(),
        late_slot,
    )
    .first()
    .cloned()
    .expect("should get at least one late attestation");

assert_eq!(
    harness.chain.process_attestation(late_attestation),
    Ok(AttestationProcessingOutcome::PastEpoch {
        attestation_epoch: current_epoch - 2,
        current_epoch
    }),
    "should not accept late attestation"
);

/*
 * Should reject attestations if the target is unknown.
 */

let mut bad_target_attestation = valid_attestation.clone();
bad_target_attestation.data.target.root = Hash256::from_low_u64_be(42);

assert_eq!(
    harness.chain.process_attestation(bad_target_attestation),
    Ok(AttestationProcessingOutcome::UnknownTargetRoot(
        Hash256::from_low_u64_be(42)
    )),
    "should not accept bad_target attestation"
);

/*
 * Should reject attestations if the target is unknown.
 */

let mut future_block_attestation = valid_attestation.clone();
future_block_attestation.data.slot -= 1;

assert_eq!(
    harness.chain.process_attestation(future_block_attestation),
    Ok(AttestationProcessingOutcome::AttestsToFutureBlock {
        block: current_slot,
        attestation: current_slot - 1
    }),
    "should not accept future_block attestation"
);

/*
 * Should reject attestations if the target is unknown.
 */

let mut bad_head_attestation = valid_attestation.clone();
bad_head_attestation.data.beacon_block_root = Hash256::from_low_u64_be(42);

assert_eq!(
    harness.chain.process_attestation(bad_head_attestation),
    Ok(AttestationProcessingOutcome::UnknownHeadBlock {
        beacon_block_root: Hash256::from_low_u64_be(42)
    }),
    "should not accept bad_head attestation"
);

/*
 * Should reject attestations with a bad signature.
 */

let mut bad_signature_attestation = valid_attestation.clone();
let kp = generate_deterministic_keypair(0);
let mut agg_sig = AggregateSignature::new();
agg_sig.add(&Signature::new(&[42, 42], &kp.sk));
bad_signature_attestation.signature = agg_sig;

assert_eq!(
    harness.chain.process_attestation(bad_signature_attestation),
    Ok(AttestationProcessingOutcome::InvalidSignature),
    "should not accept bad_signature attestation"
);

/*
 * Should reject attestations with an empty bitfield.
 */

let mut empty_bitfield_attestation = valid_attestation.clone();
empty_bitfield_attestation.aggregation_bits =
    BitList::with_capacity(1).expect("should build bitfield");

assert_eq!(
    harness
        .chain
        .process_attestation(empty_bitfield_attestation),
    Ok(AttestationProcessingOutcome::EmptyAggregationBitfield),
    "should not accept empty_bitfield attestation"
);
*/

/*
#[test]
fn attestation_that_skips_epochs() {
    let harness = get_harness(VALIDATOR_COUNT);
    let chain = &harness.chain;

    // Extend the chain out a few epochs so we have some chain depth to play with.
    harness.extend_chain(
        MainnetEthSpec::slots_per_epoch() as usize * 3 + 1,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    let current_slot = chain.slot().expect("should get slot");
    let current_epoch = chain.epoch().expect("should get epoch");

    let earlier_slot = (current_epoch - 2).start_slot(MainnetEthSpec::slots_per_epoch());
    let earlier_block = chain
        .block_at_slot(earlier_slot)
        .expect("should not error getting block at slot")
        .expect("should find block at slot");

    let mut state = chain
        .get_state(&earlier_block.state_root(), Some(earlier_slot))
        .expect("should not error getting state")
        .expect("should find state");

    while state.slot < current_slot {
        per_slot_processing(&mut state, None, &harness.spec).expect("should process slot");
    }

    let attestation = harness
        .get_unaggregated_attestations(
            &AttestationStrategy::AllValidators,
            &state,
            earlier_block.canonical_root(),
            current_slot,
        )
        .first()
        .cloned()
        .expect("should get at least one attestation");

    assert_eq!(
        harness.chain.process_attestation(attestation),
        Ok(AttestationProcessingOutcome::Processed),
        "should process attestation that skips slots"
    );
}
*/
