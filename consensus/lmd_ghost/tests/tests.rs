// TODO: remove comments
// #![cfg(not(debug_assertions))]

use beacon_chain::{
    attestation_verification::Error as AttnError,
    test_utils::{AttestationStrategy, BeaconChainHarness, BlockStrategy, HarnessType},
    BeaconSnapshot, ForkChoiceStore as BeaconForkChoiceStore, InvalidAttestation,
};
use lmd_ghost::{ForkChoice, ForkChoiceStore};
use slot_clock::{SlotClock, TestingSlotClock};
use std::sync::Arc;
use std::time::Duration;
use store::{MemoryStore, Store};
use tree_hash::TreeHash;
use types::{test_utils::generate_deterministic_keypairs, Epoch, EthSpec, MainnetEthSpec, Slot};

pub type E = MainnetEthSpec;

pub const VALIDATOR_COUNT: usize = 16;

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

/// Returns a beacon chain harness.
fn get_chain(validator_count: usize) -> Vec<BeaconSnapshot<E>> {
    let harness = BeaconChainHarness::new_with_target_aggregators(
        MainnetEthSpec,
        generate_deterministic_keypairs(VALIDATOR_COUNT),
        // A kind-of arbitrary number that ensures that _some_ validators are aggregators, but
        // not all.
        4,
    );

    harness.advance_slot();

    harness.extend_chain(
        E::slots_per_epoch() as usize * 4 - 1,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    // Advance into a slot where there have not been blocks or attestations produced.
    harness.advance_slot();

    let checkpoints = harness.chain.chain_dump().unwrap();

    let head = checkpoints.last().unwrap();

    assert_eq!(
        head.beacon_state.current_justified_checkpoint.epoch,
        Epoch::new(2)
    );

    checkpoints
}

/*
fn get_fork_choice() -> ForkChoice<BeaconForkChoiceStore<MemoryStore<E>, TestingSlotClock, E>, E> {
    let spec = E::default_spec();

    let chain = get_chain(VALIDATOR_COUNT);

    let store = Arc::new(MemoryStore::open());
    let slot_clock =
        TestingSlotClock::new(Slot::new(0), Duration::from_secs(0), Duration::from_secs(1));

    let genesis = chain.first().unwrap();

    let fc_store = BeaconForkChoiceStore::from_genesis(store, slot_clock, genesis, &spec).unwrap();

    ForkChoice::from_genesis(
        fc_store,
        genesis.beacon_block_root,
        &genesis.beacon_block.message,
        &genesis.beacon_state,
    )
    .unwrap()
}
*/

struct ForkChoiceTest {
    fc: ForkChoice<BeaconForkChoiceStore<MemoryStore<E>, TestingSlotClock, E>, E>,
    chain: Vec<BeaconSnapshot<E>>,
}

impl ForkChoiceTest {
    pub fn new() -> Self {
        let spec = E::default_spec();
        let chain = get_chain(VALIDATOR_COUNT);

        let store = Arc::new(MemoryStore::open());
        let slot_clock =
            TestingSlotClock::new(Slot::new(0), Duration::from_secs(0), Duration::from_secs(1));

        let genesis = chain.first().unwrap();

        let fc_store =
            BeaconForkChoiceStore::from_genesis(store, slot_clock, genesis, &spec).unwrap();

        let fc = ForkChoice::from_genesis(
            fc_store,
            genesis.beacon_block_root,
            &genesis.beacon_block.message,
            &genesis.beacon_state,
        )
        .unwrap();

        Self { fc, chain }
    }

    pub fn assert_justified_epoch(self, epoch: u64) -> Self {
        assert_eq!(
            self.fc.fc_store().best_justified_checkpoint().epoch,
            Epoch::new(epoch)
        );
        self
    }

    fn apply_block(&mut self, snapshot: &BeaconSnapshot<E>) {
        self.store.put_item
    }

    pub fn apply_blocks_while<F>(self, predicate: F) -> Self
    where
        F: Fn(&BeaconSnapshot<E>) -> bool,
    {
        assert_eq!(
            self.fc.fc_store().best_justified_checkpoint().epoch,
            Epoch::new(epoch)
        );
        self
    }
}

/// Tests the verification conditions for an unaggregated attestation on the gossip network.
#[test]
fn justified_checkpoint_updates() {
    ForkChoiceTest::new().assert_justified_epoch(0);
}

/*
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
                    $( ForkChoiceError::InvalidAttestation($error) ) |+ $( if $guard )?
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
        InvalidAttestation::EmptyAggregationBitfield
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
        InvalidAttestation::FutureEpoch {
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
        InvalidAttestation::PastEpoch { attestation_epoch,
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
        InvalidAttestation::BadTargetEpoch
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
        InvalidAttestation::UnknownTargetRoot(hash) if hash == unknown_root
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
        InvalidAttestation::UnknownHeadBlock {
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
        InvalidAttestation::AttestsToFutureBlock {
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
*/
