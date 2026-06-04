#![cfg(not(debug_assertions))]

use beacon_chain::attestation_simulator::produce_unaggregated_attestation;
use beacon_chain::custody_context::NodeCustodyType;
use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, fork_name_from_env,
};
use beacon_chain::validator_monitor::UNAGGREGATED_ATTESTATION_LAG_SLOTS;
use beacon_chain::{StateSkipConfig, WhenSlotSkipped, metrics};
use bls::{AggregateSignature, Keypair};
use slot_clock::SlotClock;
use std::sync::{Arc, LazyLock};
use tree_hash::TreeHash;
use types::{Attestation, EthSpec, MainnetEthSpec, RelativeEpoch, Slot};

pub const VALIDATOR_COUNT: usize = 32;

/// A cached set of keys.
static KEYPAIRS: LazyLock<Vec<Keypair>> =
    LazyLock::new(|| types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT));

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
    let hit_prometheus_metrics = [
        metrics::VALIDATOR_MONITOR_ATTESTATION_SIMULATOR_HEAD_ATTESTER_HIT_TOTAL,
        metrics::VALIDATOR_MONITOR_ATTESTATION_SIMULATOR_TARGET_ATTESTER_HIT_TOTAL,
        metrics::VALIDATOR_MONITOR_ATTESTATION_SIMULATOR_SOURCE_ATTESTER_HIT_TOTAL,
    ];
    let miss_prometheus_metrics = [
        metrics::VALIDATOR_MONITOR_ATTESTATION_SIMULATOR_HEAD_ATTESTER_MISS_TOTAL,
        metrics::VALIDATOR_MONITOR_ATTESTATION_SIMULATOR_TARGET_ATTESTER_MISS_TOTAL,
        metrics::VALIDATOR_MONITOR_ATTESTATION_SIMULATOR_SOURCE_ATTESTER_MISS_TOTAL,
    ];

    // Expected metrics count should only apply to hit metrics as miss metrics are never set, nor can be found
    // when gathering prometheus metrics. If they are found, which should not, it will diff from 0 and fail the test
    let expected_miss_metrics_count = 0;
    let expected_hit_metrics_count =
        num_blocks_produced - UNAGGREGATED_ATTESTATION_LAG_SLOTS as u64;
    metrics::gather().iter().for_each(|mf| {
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
        // SemiSupernode ensures enough columns are stored for sampling + custody validation for RpcBlock
        .node_custody_type(NodeCustodyType::SemiSupernode)
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

            let (aggregation_bits_len, aggregation_bits_zero) = match &attestation {
                Attestation::Base(att) => {
                    (att.aggregation_bits.len(), att.aggregation_bits.is_zero())
                }
                Attestation::Electra(att) => {
                    (att.aggregation_bits.len(), att.aggregation_bits.is_zero())
                }
            };
            assert_eq!(aggregation_bits_len, committee_len, "bad committee len");
            assert!(aggregation_bits_zero, "some committee bits are set");

            let data = attestation.data();

            assert_eq!(
                attestation.signature(),
                &AggregateSignature::infinity(),
                "bad signature"
            );
            if harness
                .spec
                .fork_name_at_slot::<MainnetEthSpec>(data.slot)
                .gloas_enabled()
            {
                assert!(data.index <= 1, "invalid index");
            } else {
                assert_eq!(data.index, index, "bad index");
            }
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

            let range_sync_block = harness
                .build_range_sync_block_from_store_blobs(Some(block_root), Arc::new(block.clone()));
            let available_block = range_sync_block.into_available_block();

            // For Gloas non-same-slot attestations, the early attester cache returns None.
            let is_same_slot_attestation = slot == block_slot;
            let is_gloas = harness
                .spec
                .fork_name_at_slot::<MainnetEthSpec>(slot)
                .gloas_enabled();
            if !is_gloas || is_same_slot_attestation {
                let early_attestation = {
                    let proto_block = chain
                        .canonical_head
                        .fork_choice_read_lock()
                        .get_block(&block_root)
                        .unwrap();
                    chain
                        .early_attester_cache
                        .add_head_block(block_root, &available_block, proto_block, &state)
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

    let available_block = harness
        .build_range_sync_block_from_store_blobs(
            Some(head.beacon_block_root),
            head.beacon_block.clone(),
        )
        .into_available_block();

    harness
        .chain
        .early_attester_cache
        .add_head_block(
            head.beacon_block_root,
            &available_block,
            head_proto_block,
            &head.beacon_state,
        )
        .unwrap();

    let attest_slot = head.beacon_block.slot() - 1;
    let attestation = harness
        .chain
        .produce_unaggregated_attestation(attest_slot, 0)
        .unwrap();

    assert_eq!(attestation.data().slot, attest_slot);
    let attested_block = harness
        .chain
        .get_blinded_block(&attestation.data().beacon_block_root)
        .unwrap()
        .unwrap();
    assert_eq!(attested_block.slot(), attest_slot);
}

/// Verify that `produce_unaggregated_attestation` sets `data.index = 1` (payload_present)
/// when a gloas validator attests to a prior slot whose block+envelope have been received.
///
/// Setup: build a chain at gloas genesis, produce a block with envelope at slot N,
/// then advance the clock to slot N+1 without producing a block (skipped slot).
/// Attesting at slot N+1 should target the block at slot N with payload_present = true.
#[tokio::test]
async fn gloas_attestation_index_payload_present() {
    if fork_name_from_env().is_some_and(|f| !f.gloas_enabled()) {
        return;
    }

    let harness = BeaconChainHarness::builder(MainnetEthSpec)
        .default_spec()
        .keypairs(KEYPAIRS[..].to_vec())
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    let chain = &harness.chain;

    // Build a few blocks so the chain is established (slots 1..=3).
    harness.advance_slot();
    harness
        .extend_chain(
            3,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let head = chain.head_snapshot();
    assert_eq!(head.beacon_block.slot(), Slot::new(3));

    // Advance clock to slot 4 without producing a block (skipped slot).
    harness.advance_slot();
    let attest_slot = chain.slot().unwrap();
    assert_eq!(attest_slot, Slot::new(4));

    // Attest at slot 4 — this should target the block at slot 3 whose payload was received.
    let attestation = chain
        .produce_unaggregated_attestation(attest_slot, 0)
        .expect("should produce attestation");

    assert_eq!(attestation.data().slot, attest_slot);
    assert_eq!(
        attestation.data().index,
        1,
        "gloas attestation to prior slot with payload should have index=1 (payload_present)"
    );
}

/// Verify that `produce_unaggregated_attestation` sets `data.index = 0` (payload NOT present)
/// when a gloas validator attests to a prior slot whose block was imported but whose
/// payload envelope was never received.
///
/// Setup: build a chain at gloas genesis through slot 2, then at slot 3 import only the
/// beacon block (no envelope), advance to slot 4 (skipped), and attest.
#[tokio::test]
async fn gloas_attestation_index_payload_absent() {
    if fork_name_from_env().is_some_and(|f| !f.gloas_enabled()) {
        return;
    }

    let harness = BeaconChainHarness::builder(MainnetEthSpec)
        .default_spec()
        .keypairs(KEYPAIRS[..].to_vec())
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    let chain = &harness.chain;

    // Build slots 1..=2 normally (with envelopes).
    harness.advance_slot();
    harness
        .extend_chain(
            2,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    assert_eq!(chain.head_snapshot().beacon_block.slot(), Slot::new(2));

    // Slot 3: produce and import the beacon block but do NOT process the envelope.
    harness.advance_slot();
    let state = harness.get_current_state();
    let (block_contents, _envelope, _new_state) =
        harness.make_block_with_envelope(state, Slot::new(3)).await;

    let block_root = block_contents.0.canonical_root();
    harness
        .process_block(Slot::new(3), block_root, block_contents)
        .await
        .expect("block should import without envelope");

    assert_eq!(chain.head_snapshot().beacon_block.slot(), Slot::new(3));

    // Advance clock to slot 4 without producing a block (skipped slot).
    harness.advance_slot();
    let attest_slot = chain.slot().unwrap();
    assert_eq!(attest_slot, Slot::new(4));

    // Attest at slot 4 — targets slot 3 whose payload was NOT received.
    let attestation = chain
        .produce_unaggregated_attestation(attest_slot, 0)
        .expect("should produce attestation");

    assert_eq!(attestation.data().slot, attest_slot);
    assert_eq!(
        attestation.data().index,
        0,
        "gloas attestation to prior slot without payload should have index=0 (payload_absent)"
    );
}

/// Verify that `produce_payload_attestation_data` reports `payload_present = true` but
/// `blob_data_available = false` when the envelope was observed on but not imported
/// because its data was unavailable.
///
/// Setup: build a chain through slot 2, then at slot 3 import only the beacon block (no
/// envelope) and mark the envelope as observed on time.
#[tokio::test]
async fn gloas_payload_attestation_seen_but_data_unavailable() {
    if fork_name_from_env().is_some_and(|f| !f.gloas_enabled()) {
        return;
    }

    let harness = BeaconChainHarness::builder(MainnetEthSpec)
        .default_spec()
        .keypairs(KEYPAIRS[..].to_vec())
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    let chain = &harness.chain;

    harness.advance_slot();
    harness
        .extend_chain(
            2,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Slot 3: import the beacon block but withhold its envelope.
    harness.advance_slot();
    let state = harness.get_current_state();
    let (block_contents, _envelope, _new_state) =
        harness.make_block_with_envelope(state, Slot::new(3)).await;
    let block_root = block_contents.0.canonical_root();
    harness
        .process_block(Slot::new(3), block_root, block_contents)
        .await
        .expect("block should import without envelope");

    assert_eq!(chain.head_snapshot().beacon_block.slot(), Slot::new(3));

    // Mark the envelope as observed at the start of the slot, before its deadline.
    let slot_start = chain.slot_clock.start_of(Slot::new(3)).unwrap();
    chain.envelope_times_cache.write().set_time_observed(
        block_root,
        Slot::new(3),
        slot_start,
        None,
    );

    let pa_data = chain
        .produce_payload_attestation_data(Slot::new(3))
        .expect("should produce payload attestation data");

    assert!(
        pa_data.payload_present,
        "envelope observed before the deadline should vote payload_present=true"
    );
    assert!(
        !pa_data.blob_data_available,
        "unimported envelope data should vote blob_data_available=false"
    );
}
