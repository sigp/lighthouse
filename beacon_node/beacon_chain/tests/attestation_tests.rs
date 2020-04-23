// #![cfg(not(debug_assertions))]

#[macro_use]
extern crate lazy_static;

use beacon_chain::AttestationProcessingOutcome;
use beacon_chain::{
    attestation_verification::{Error as AttnError, VerifiedUnaggregatedAttestation},
    test_utils::{AttestationStrategy, BeaconChainHarness, BlockStrategy, HarnessType},
    BeaconChain,
};
use state_processing::per_slot_processing;
use types::{
    test_utils::generate_deterministic_keypair, AggregateSignature, Attestation, BitList, EthSpec,
    Hash256, Keypair, MainnetEthSpec, Signature, Slot,
};

pub type E = MainnetEthSpec;

pub const VALIDATOR_COUNT: usize = 128;

lazy_static! {
    /// A cached set of keys.
    static ref KEYPAIRS: Vec<Keypair> = types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT);
}

fn get_harness(validator_count: usize) -> BeaconChainHarness<HarnessType<E>> {
    let harness = BeaconChainHarness::new(MainnetEthSpec, KEYPAIRS[0..validator_count].to_vec());

    harness.advance_slot();

    harness
}

/// This test is "general" because it tests several things to avoid the overhead of spinning up
/// lots of beacon chain harnesses.
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

    let head = chain.head().expect("should get head");
    let current_slot = chain.slot().expect("should get slot");
    let current_epoch = chain.epoch().expect("should get epoch");

    assert_eq!(
        current_slot % E::slots_per_epoch(),
        0,
        "the test requires a new epoch to avoid already-seen errors"
    );

    let mut valid_attestation = harness
        .chain
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
            harness.chain.genesis_validators_root,
            &harness.chain.spec,
        )
        .expect("should sign attestation");

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

    let awkward_root = Hash256::from_low_u64_le(424242); // No one wants one of these
    assert_invalid!(
        "attestation with unknown head block",
        {
            let mut a = valid_attestation.clone();
            a.data.beacon_block_root = awkward_root;
            a
        },
        AttnError::UnknownHeadBlock {
            beacon_block_root: awkward_root
        }
    );

    let awkward_root = Hash256::from_low_u64_le(424242); // No one wants one of these
    assert_invalid!(
        "attestation with unknown head block",
        {
            let mut a = valid_attestation.clone();
            a.data.beacon_block_root = awkward_root;
            a
        },
        AttnError::UnknownHeadBlock {
            beacon_block_root: awkward_root
        }
    );

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

    assert_invalid!(
        "attestation that has already been seen",
        valid_attestation.clone(),
        AttnError::PriorAttestationKnown {
            validator_index: validator_index as u64,
            epoch: current_epoch
        }
    );

    // TODO: double check first valid attestation thing.

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
}

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
