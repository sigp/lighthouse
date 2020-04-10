// #![cfg(not(debug_assertions))]

/*
#[macro_use]
extern crate lazy_static;

use beacon_chain::test_utils::{
    AttestationError, AttestationStrategy, BeaconChain, BeaconChainHarness, BlockStrategy,
    HarnessType,
};
use beacon_chain::{AttestationProcessingOutcome, AttestationType};
use state_processing::per_slot_processing;
use types::{
    test_utils::generate_deterministic_keypair, AggregateSignature, Attestation, BitList, EthSpec,
    Hash256, Keypair, MainnetEthSpec, Signature,
};

pub const VALIDATOR_COUNT: usize = 128;

lazy_static! {
    /// A cached set of keys.
    static ref KEYPAIRS: Vec<Keypair> = types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT);
}

fn get_harness(validator_count: usize) -> BeaconChainHarness<HarnessType<MainnetEthSpec>> {
    let harness = BeaconChainHarness::new(MainnetEthSpec, KEYPAIRS[0..validator_count].to_vec());

    harness.advance_slot();

    harness
}

fn process_gossip_attestation<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    attestation: &Attestation<T::EthSpec>,
) -> Result<(), AttestationError> {
    let gossip_attestation = chain.verify_unaggregated_attestation_for_gossip()?;
    let fc_attestation =
}

#[test]
fn attestation_validity() {
    let harness = get_harness(VALIDATOR_COUNT);
    let chain = &harness.chain;

    // Extend the chain out a few epochs so we have some chain depth to play with.
    harness.extend_chain(
        MainnetEthSpec::slots_per_epoch() as usize * 3 + 1,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    let head = chain.head().expect("should get head");
    let current_slot = chain.slot().expect("should get slot");
    let current_epoch = chain.epoch().expect("should get epoch");

    let valid_attestation = harness
        .get_unaggregated_attestations(
            &AttestationStrategy::AllValidators,
            &head.beacon_state,
            head.beacon_block_root,
            head.beacon_block.slot(),
        )
        .first()
        .cloned()
        .expect("should get at least one attestation");

    assert_eq!(
        chain.process_attestation(valid_attestation.clone(), AttestationType::Aggregated),
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
            .process_attestation(epoch_mismatch_attestation, AttestationType::Aggregated),
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
        harness
            .chain
            .process_attestation(early_attestation, AttestationType::Aggregated),
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
        harness
            .chain
            .process_attestation(late_attestation, AttestationType::Aggregated),
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
        harness
            .chain
            .process_attestation(bad_target_attestation, AttestationType::Aggregated),
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
        harness
            .chain
            .process_attestation(future_block_attestation, AttestationType::Aggregated),
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
        harness
            .chain
            .process_attestation(bad_head_attestation, AttestationType::Aggregated),
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
        harness
            .chain
            .process_attestation(bad_signature_attestation, AttestationType::Aggregated),
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
            .process_attestation(empty_bitfield_attestation, AttestationType::Aggregated),
        Ok(AttestationProcessingOutcome::EmptyAggregationBitfield),
        "should not accept empty_bitfield attestation"
    );
}

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
        harness
            .chain
            .process_attestation(attestation, AttestationType::Aggregated),
        Ok(AttestationProcessingOutcome::Processed),
        "should process attestation that skips slots"
    );
}
*/
