use beacon_chain::attestation_simulator::produce_unaggregated_attestation;
use beacon_chain::test_utils::{AttestationStrategy, BeaconChainHarness, BlockStrategy};
use beacon_chain::validator_monitor::UNAGGREGATED_ATTESTATION_LAG_SLOTS;
use beacon_chain::{metrics, StateSkipConfig, WhenSlotSkipped};
use lazy_static::lazy_static;
use std::sync::Arc;
use tree_hash::TreeHash;
use types::{AggregateSignature, EthSpec, Keypair, MainnetEthSpec, RelativeEpoch, Slot};

pub const VALIDATOR_COUNT: usize = 16;

lazy_static! {
    /// A cached set of keys.
    static ref KEYPAIRS: Vec<Keypair> = types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT);
}

/// This test builds a chain that is testing the performance of the unaggregated attestations
/// produced by the attestation simulator service.
#[tokio::test]
async fn produces_attestations_from_attestation_simulator_service() {
    // Produce 2 epochs, or 64 blocks
    let num_blocks_produced = MainnetEthSpec::slots_per_epoch() * 2;

    let harness = BeaconChainHarness::builder(MainnetEthSpec)
        .default_spec()
        .keypairs(KEYPAIRS[..].to_vec())
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    let chain = &harness.chain;

    // Test all valid committee indices and their rewards for all slots in the chain
    // using validator monitor
    for slot in 0..=num_blocks_produced {
        // We do not produce at slot=0, and there's no committe cache available anyway
        if slot > 0 && slot <= num_blocks_produced {
            harness.advance_slot();

            harness
                .extend_chain(
                    1,
                    BlockStrategy::OnCanonicalHead,
                    AttestationStrategy::AllValidators,
                )
                .await;
        }
        // Set the state to the current slot
        let slot = Slot::from(slot);
        let mut state = chain
            .state_at_slot(slot, StateSkipConfig::WithStateRoots)
            .expect("should get state");

        // Prebuild the committee cache for the current epoch
        state
            .build_committee_cache(RelativeEpoch::Current, &harness.chain.spec)
            .unwrap();

        // Produce an unaggragetated attestation
        produce_unaggregated_attestation(chain.clone(), chain.slot().unwrap());

        // Verify that the ua is stored in validator monitor
        let validator_monitor = chain.validator_monitor.read();
        validator_monitor
            .get_unaggregated_attestation(slot)
            .expect("should get unaggregated attestation");
    }

    // Compare the prometheus metrics that evaluates the performance of the unaggregated attestations
    let hit_prometheus_metrics = vec![
        metrics::VALIDATOR_MONITOR_ATTESTATION_SIMULATOR_HEAD_ATTESTER_HIT_TOTAL,
        metrics::VALIDATOR_MONITOR_ATTESTATION_SIMULATOR_TARGET_ATTESTER_HIT_TOTAL,
        metrics::VALIDATOR_MONITOR_ATTESTATION_SIMULATOR_SOURCE_ATTESTER_HIT_TOTAL,
    ];
    let miss_prometheus_metrics = vec![
        metrics::VALIDATOR_MONITOR_ATTESTATION_SIMULATOR_HEAD_ATTESTER_MISS_TOTAL,
        metrics::VALIDATOR_MONITOR_ATTESTATION_SIMULATOR_TARGET_ATTESTER_MISS_TOTAL,
        metrics::VALIDATOR_MONITOR_ATTESTATION_SIMULATOR_SOURCE_ATTESTER_MISS_TOTAL,
    ];

    // Expected metrics count should only apply to hit metrics as miss metrics are never set, nor can be found
    // when gathering prometheus metrics. If they are found, which should not, it will diff from 0 and fail the test
    let expected_miss_metrics_count = 0;
    let expected_hit_metrics_count =
        num_blocks_produced - UNAGGREGATED_ATTESTATION_LAG_SLOTS as u64;
    lighthouse_metrics::gather().iter().for_each(|mf| {
        if hit_prometheus_metrics.contains(&mf.get_name()) {
            assert_eq!(
                mf.get_metric()[0].get_counter().get_value() as u64,
                expected_hit_metrics_count
            );
        }
        if miss_prometheus_metrics.contains(&mf.get_name()) {
            assert_eq!(
                mf.get_metric()[0].get_counter().get_value() as u64,
                expected_miss_metrics_count
            );
        }
    });
}

/// This test builds a chain that is just long enough to finalize an epoch then it produces an
/// attestation at each slot from genesis through to three epochs past the head.
///
/// It checks the produced attestation against some locally computed values.
#[tokio::test]
async fn produces_attestations() {
    let num_blocks_produced = MainnetEthSpec::slots_per_epoch() * 4;
    let additional_slots_tested = MainnetEthSpec::slots_per_epoch() * 3;

    let harness = BeaconChainHarness::builder(MainnetEthSpec)
        .default_spec()
        .keypairs(KEYPAIRS[..].to_vec())
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    let chain = &harness.chain;

    // Test all valid committee indices for all slots in the chain.
    // for slot in 0..=current_slot.as_u64() + MainnetEthSpec::slots_per_epoch() * 3 {
    for slot in 0..=num_blocks_produced + additional_slots_tested {
        if slot > 0 && slot <= num_blocks_produced {
            harness.advance_slot();

            harness
                .extend_chain(
                    1,
                    BlockStrategy::OnCanonicalHead,
                    AttestationStrategy::AllValidators,
                )
                .await;
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

        let blinded_block = chain
            .block_at_slot(block_slot, WhenSlotSkipped::Prev)
            .expect("should get block")
            .expect("block should not be skipped");
        let block_root = blinded_block.message().tree_hash_root();
        let block = chain
            .store
            .make_full_block(&block_root, blinded_block)
            .unwrap();

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

            let early_attestation = {
                let proto_block = chain
                    .canonical_head
                    .fork_choice_read_lock()
                    .get_block(&block_root)
                    .unwrap();
                chain
                    .early_attester_cache
                    .add_head_block(
                        block_root,
                        Arc::new(block.clone()),
                        proto_block,
                        &state,
                        &chain.spec,
                    )
                    .unwrap();
                chain
                    .early_attester_cache
                    .try_attest(slot, index, &chain.spec)
                    .unwrap()
                    .unwrap()
            };

            assert_eq!(
                attestation, early_attestation,
                "early attester cache inconsistent"
            );
        }
    }
}

/// Ensures that the early attester cache wont create an attestation to a block in a later slot than
/// the one requested.
#[tokio::test]
async fn early_attester_cache_old_request() {
    let harness = BeaconChainHarness::builder(MainnetEthSpec)
        .default_spec()
        .keypairs(KEYPAIRS[..].to_vec())
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    harness.advance_slot();

    harness
        .extend_chain(
            2,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let head = harness.chain.head_snapshot();
    assert_eq!(head.beacon_block.slot(), 2);
    let head_proto_block = harness
        .chain
        .canonical_head
        .fork_choice_read_lock()
        .get_block(&head.beacon_block_root)
        .unwrap();

    harness
        .chain
        .early_attester_cache
        .add_head_block(
            head.beacon_block_root,
            head.beacon_block.clone(),
            head_proto_block,
            &head.beacon_state,
            &harness.chain.spec,
        )
        .unwrap();

    let attest_slot = head.beacon_block.slot() - 1;
    let attestation = harness
        .chain
        .produce_unaggregated_attestation(attest_slot, 0)
        .unwrap();

    assert_eq!(attestation.data.slot, attest_slot);
    let attested_block = harness
        .chain
        .get_blinded_block(&attestation.data.beacon_block_root)
        .unwrap()
        .unwrap();
    assert_eq!(attested_block.slot(), attest_slot);
}
