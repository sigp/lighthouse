#![cfg(not(debug_assertions))]

#[macro_use]
extern crate lazy_static;

use beacon_chain::{
    attestation_verification::Error as AttnError,
    test_utils::{AttestationStrategy, BeaconChainHarness, BlockStrategy, HarnessType},
    BeaconChain, BeaconChainTypes,
};
use state_processing::per_slot_processing;
use store::Store;
use tree_hash::TreeHash;
use types::{
    test_utils::generate_deterministic_keypair, AggregateSignature, Attestation, EthSpec, Hash256,
    Keypair, MainnetEthSpec, SecretKey, SelectionProof, Signature, SignedAggregateAndProof,
    SignedBeaconBlock, Unsigned,
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
    mut aggregate: Attestation<T::EthSpec>,
) -> (SignedAggregateAndProof<T::EthSpec>, usize, SecretKey) {
    let state = &chain.head().expect("should get head").beacon_state;
    let current_slot = chain.slot().expect("should get slot");

    let committee = state
        .get_beacon_committee(current_slot, aggregate.data.index)
        .expect("should get committees");
    let committee_len = committee.committee.len();

    let (aggregator_committee_pos, aggregator_index, aggregator_sk) = committee
        .committee
        .iter()
        .enumerate()
        .find_map(|(committee_pos, &val_index)| {
            let aggregator_sk = generate_deterministic_keypair(val_index).sk;

            let proof = SelectionProof::new::<T::EthSpec>(
                aggregate.data.slot,
                &aggregator_sk,
                &state.fork,
                chain.genesis_validators_root,
                &chain.spec,
            );

            if proof.is_aggregator(committee_len, &chain.spec).unwrap() {
                Some((committee_pos, val_index, aggregator_sk))
            } else {
                None
            }
        })
        .expect("should find aggregator for committee");

    // FIXME(v0.12): this can be removed once the verification rules are updated for v0.12
    // I needed to add it because the test only *happened* to work because aggregator and attester
    // indices were the same before!
    aggregate
        .sign(
            &aggregator_sk,
            aggregator_committee_pos,
            &state.fork,
            chain.genesis_validators_root,
            &chain.spec,
        )
        .expect("should sign attestation");

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
     * Spec v0.11.2
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
        if attestation_slot == early_slot && earliest_permissible_slot == current_slot - E::slots_per_epoch() - 1
    );

    /*
     * The following test ensures:
     *
     * Spec v0.11.2
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
     * This test ensures:
     *
     * Spec v0.11.2
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
     * Spec v0.11.2
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
     * Spec v0.11.2
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
        AttnError::ValidatorIndexTooHigh(index)
        if index == too_high_index as usize
    );

    /*
     * The following test ensures:
     *
     * Spec v0.11.2
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
            aggregator_index
        }
        if aggregator_index == unknown_validator
    );

    /*
     * The following test ensures:
     *
     * Spec v0.11.2
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
     * NOTE: this is a slight deviation from the spec, see:
     * https://github.com/ethereum/eth2.0-specs/pull/1749
     *
     * Spec v0.11.2
     *
     * The aggregate attestation defined by hash_tree_root(aggregate) has not already been seen
     * (via aggregate gossip, within a block, or through the creation of an equivalent aggregate
     * locally).
     */

    assert_invalid!(
        "aggregate with that has already been seen",
        valid_aggregate.clone(),
        AttnError::AttestationAlreadyKnown(hash)
        if hash == valid_aggregate.message.aggregate.tree_hash_root()
    );

    /*
     * The following test ensures:
     *
     * Spec v0.11.2
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

    let (valid_attestation, expected_validator_index, validator_committee_index, validator_sk) =
        get_valid_unaggregated_attestation(&harness.chain);

    macro_rules! assert_invalid {
        ($desc: tt, $attn_getter: expr, $($error: pat) |+ $( if $guard: expr )?) => {
            assert!(
                matches!(
                    harness
                        .chain
                        .verify_unaggregated_attestation_for_gossip($attn_getter)
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
     * The following two tests ensure:
     *
     * Spec v0.11.2
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
            a
        },
        AttnError::PastSlot {
            attestation_slot,
            // Subtract an additional slot since the harness will be exactly on the start of the
            // slot and the propagation tolerance will allow an extra slot.
            earliest_permissible_slot,
        }
        if attestation_slot == early_slot && earliest_permissible_slot == current_slot - E::slots_per_epoch() - 1
    );

    /*
     * The following two tests ensure:
     *
     * Spec v0.11.2
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
     * Spec v0.11.2
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
            beacon_block_root,
        }
        if beacon_block_root == unknown_root
    );

    /*
     * The following test ensures that:
     *
     * Spec v0.11.2
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
     * Spec v0.11.2
     *
     *
     * There has been no other valid attestation seen on an attestation subnet that has an
     * identical attestation.data.target.epoch and participating validator index.
     */

    assert_invalid!(
        "attestation that has already been seen",
        valid_attestation.clone(),
        AttnError::PriorAttestationKnown {
            validator_index,
            epoch,
        }
        if validator_index == expected_validator_index as u64 && epoch == current_epoch
    );
}

/// Tests the verification conditions for an unaggregated attestation on the gossip network.
#[test]
fn fork_choice_verification() {
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

    // We're going to produce the attestations at the first slot of the epoch.
    let (valid_attestation, _validator_index, _validator_committee_index, _validator_sk) =
        get_valid_unaggregated_attestation(&harness.chain);

    // Extend the chain two more blocks, but without any attestations so we don't trigger the
    // "already seen" caches.
    //
    // Because of this, the attestation we're dealing with was made one slot prior to the current
    // slot. This allows us to test the `AttestsToFutureBlock` condition.
    harness.extend_chain(
        2,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::SomeValidators(vec![]),
    );

    let current_slot = chain.slot().expect("should get slot");
    let expected_current_epoch = chain.epoch().expect("should get epoch");

    let attestation = harness
        .chain
        .verify_unaggregated_attestation_for_gossip(valid_attestation.clone())
        .expect("precondition: should gossip verify attestation");

    macro_rules! assert_invalid {
        ($desc: tt, $attn_getter: expr, $($error: pat) |+ $( if $guard: expr )?) => {
            assert!(
                matches!(
                    harness
                        .chain
                        .apply_attestation_to_fork_choice(&$attn_getter)
                        .err()
                        .expect(&format!(
                            "{} should error during apply_attestation_to_fork_choice",
                            $desc
                        )),
                    $( $error ) |+ $( if $guard )?
                ),
                "case: {}",
                $desc,
            );
        };
    }

    assert_invalid!(
        "attestation without any aggregation bits set",
        {
            let mut a = attestation.clone();
            a.__indexed_attestation_mut().attesting_indices = vec![].into();
            a
        },
        AttnError::EmptyAggregationBitfield
    );

    /*
     * The following two tests ensure that:
     *
     * Spec v0.11.2
     *
     * assert target.epoch in [expected_current_epoch, previous_epoch]
     */

    let future_epoch = expected_current_epoch + 1;
    assert_invalid!(
        "attestation from future epoch",
        {
            let mut a = attestation.clone();
            a.__indexed_attestation_mut().data.target.epoch = future_epoch;
            a
        },
        AttnError::FutureEpoch {
            attestation_epoch,
            current_epoch,
        }
        if attestation_epoch == future_epoch && current_epoch == expected_current_epoch
    );

    assert!(
        expected_current_epoch > 1,
        "precondition: must be able to have a past epoch"
    );

    let past_epoch = expected_current_epoch - 2;
    assert_invalid!(
        "attestation from past epoch",
        {
            let mut a = attestation.clone();
            a.__indexed_attestation_mut().data.target.epoch = past_epoch;
            a
        },
        AttnError::PastEpoch {
            attestation_epoch,
            current_epoch,
        }
        if attestation_epoch == past_epoch && current_epoch == expected_current_epoch
    );

    /*
     * This test ensures that:
     *
     * Spec v0.11.2
     *
     * assert target.epoch == compute_epoch_at_slot(attestation.data.slot)
     */

    assert_invalid!(
        "attestation with bad target epoch",
        {
            let mut a = attestation.clone();

            let indexed = a.__indexed_attestation_mut();
            indexed.data.target.epoch = indexed.data.slot.epoch(E::slots_per_epoch()) - 1;
            a
        },
        AttnError::BadTargetEpoch
    );

    /*
     * This test ensures that:
     *
     * Spec v0.11.2
     *
     * Attestations target be for a known block. If target block is unknown, delay consideration
     * until the block is found
     *
     * assert target.root in store.blocks
     */

    let unknown_root = Hash256::from_low_u64_le(42);
    assert_invalid!(
        "attestation with unknown target root",
        {
            let mut a = attestation.clone();

            let indexed = a.__indexed_attestation_mut();
            indexed.data.target.root = unknown_root;
            a
        },
        AttnError::UnknownTargetRoot(hash) if hash == unknown_root
    );

    // NOTE: we're not testing an assert from the spec:
    //
    // `assert get_current_slot(store) >= compute_start_slot_at_epoch(target.epoch)`
    //
    // I think this check is redundant and I've raised an issue here:
    //
    // https://github.com/ethereum/eth2.0-specs/pull/1755

    /*
     * This test asserts that:
     *
     * Spec v0.11.2
     *
     * # Attestations must be for a known block. If block is unknown, delay consideration until the
     * block is found
     *
     * assert attestation.data.beacon_block_root in store.blocks
     */

    assert_invalid!(
        "attestation with unknown beacon block root",
        {
            let mut a = attestation.clone();

            let indexed = a.__indexed_attestation_mut();
            indexed.data.beacon_block_root = unknown_root;
            a
        },
        AttnError::UnknownHeadBlock {
            beacon_block_root
        }
        if beacon_block_root == unknown_root
    );

    let future_block = harness
        .chain
        .block_at_slot(current_slot)
        .expect("should not error getting block")
        .expect("should find block at current slot");
    assert_invalid!(
        "attestation to future block",
        {
            let mut a = attestation.clone();

            let indexed = a.__indexed_attestation_mut();

            assert!(
                future_block.slot() > indexed.data.slot,
                "precondition: the attestation must attest to the future"
            );

            indexed.data.beacon_block_root = future_block.canonical_root();
            a
        },
        AttnError::AttestsToFutureBlock {
            block: current_slot,
            attestation: slot,
        }
        if slot == current_slot - 1
    );

    // Note: we're not checking the "attestations can only affect the fork choice of subsequent
    // slots" part of the spec, we do this upstream.

    assert!(
        harness
            .chain
            .apply_attestation_to_fork_choice(&attestation.clone())
            .is_ok(),
        "should verify valid attestation"
    );

    // There's nothing stopping fork choice from accepting the same attestation twice.
    assert!(
        harness
            .chain
            .apply_attestation_to_fork_choice(&attestation)
            .is_ok(),
        "should verify valid attestation a second time"
    );
}

/// Ensures that an attestation that skips epochs can still be processed.
///
/// This also checks that we can do a state lookup if we don't get a hit from the shuffling cache.
#[test]
fn attestation_that_skips_epochs() {
    let harness = get_harness(VALIDATOR_COUNT);
    let chain = &harness.chain;

    // Extend the chain out a few epochs so we have some chain depth to play with.
    harness.extend_chain(
        MainnetEthSpec::slots_per_epoch() as usize * 3 + 1,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::SomeValidators(vec![]),
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
        .verify_unaggregated_attestation_for_gossip(attestation)
        .expect("should gossip verify attestation that skips slots");
}
