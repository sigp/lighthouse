#![cfg(not(debug_assertions))]

#[macro_use]
extern crate lazy_static;

use beacon_chain::test_utils::{AttestationStrategy, BeaconChainHarness, BlockStrategy};
use beacon_chain::{StateSkipConfig, WhenSlotSkipped};
use tree_hash::TreeHash;
use types::{AggregateSignature, EthSpec, Keypair, MainnetEthSpec, RelativeEpoch, Slot};

pub const VALIDATOR_COUNT: usize = 16;

lazy_static! {
    /// A cached set of keys.
    static ref KEYPAIRS: Vec<Keypair> = types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT);
}

/// This test builds a chain that is just long enough to finalize an epoch then it produces an
/// attestation at each slot from genesis through to three epochs past the head.
///
/// It checks the produced attestation against some locally computed values.
#[test]
fn produces_attestations() {
    let num_blocks_produced = MainnetEthSpec::slots_per_epoch() * 4;
    let additional_slots_tested = MainnetEthSpec::slots_per_epoch() * 3;

    let harness = BeaconChainHarness::builder(MainnetEthSpec)
        .default_spec()
        .keypairs(KEYPAIRS[..].to_vec())
        .fresh_ephemeral_store()
        .build();

    let chain = &harness.chain;

    // Test all valid committee indices for all slots in the chain.
    // for slot in 0..=current_slot.as_u64() + MainnetEthSpec::slots_per_epoch() * 3 {
    for slot in 0..=num_blocks_produced + additional_slots_tested {
        if slot > 0 && slot <= num_blocks_produced {
            harness.advance_slot();

            harness.extend_chain(
                1,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::AllValidators,
            );
        }

        let slot = Slot::from(slot);
        let mut state = chain
            .state_at_slot(slot, StateSkipConfig::WithStateRoots)
            .expect("should get state");

        let block_slot = if slot <= num_blocks_produced {
            slot
        } else {
            Slot::from(num_blocks_produced)
        };

        let block = chain
            .block_at_slot(block_slot, WhenSlotSkipped::Prev)
            .expect("should get block")
            .expect("block should not be skipped");
        let block_root = block.message().tree_hash_root();

        let epoch_boundary_slot = state
            .current_epoch()
            .start_slot(MainnetEthSpec::slots_per_epoch());
        let target_root = if state.slot() == epoch_boundary_slot {
            block_root
        } else {
            *state
                .get_block_root(epoch_boundary_slot)
                .expect("should get target block root")
        };

        state
            .build_committee_cache(RelativeEpoch::Current, &harness.chain.spec)
            .unwrap();
        let committee_cache = state
            .committee_cache(RelativeEpoch::Current)
            .expect("should get committee_cache");

        let committee_count = committee_cache.committees_per_slot();

        for index in 0..committee_count {
            let committee_len = committee_cache
                .get_beacon_committee(slot, index)
                .expect("should get committee for slot")
                .committee
                .len();

            let attestation = chain
                .produce_unaggregated_attestation(slot, index)
                .expect("should produce attestation");

            let data = &attestation.data;

            assert_eq!(
                attestation.aggregation_bits.len(),
                committee_len,
                "bad committee len"
            );
            assert!(
                attestation.aggregation_bits.is_zero(),
                "some committee bits are set"
            );
            assert_eq!(
                attestation.signature,
                AggregateSignature::empty(),
                "bad signature"
            );
            assert_eq!(data.index, index, "bad index");
            assert_eq!(data.slot, slot, "bad slot");
            assert_eq!(data.beacon_block_root, block_root, "bad block root");
            assert_eq!(
                data.source,
                state.current_justified_checkpoint(),
                "bad source"
            );
            assert_eq!(
                data.source,
                state.current_justified_checkpoint(),
                "bad source"
            );
            assert_eq!(data.target.epoch, state.current_epoch(), "bad target epoch");
            assert_eq!(data.target.root, target_root, "bad target root");
        }
    }
}
