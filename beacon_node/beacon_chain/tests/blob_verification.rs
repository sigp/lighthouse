#![cfg(not(debug_assertions))]

use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType, test_spec,
};
use beacon_chain::{
    AvailabilityProcessingStatus, BlockError, ChainConfig, InvalidSignature, NotifyExecutionLayer,
    block_verification_types::AsBlock,
};
use logging::create_test_tracing_subscriber;
use std::sync::{Arc, LazyLock};
use types::{blob_sidecar::FixedBlobSidecarList, *};

type E = MainnetEthSpec;

// Should ideally be divisible by 3.
const VALIDATOR_COUNT: usize = 24;

/// A cached set of keys.
static KEYPAIRS: LazyLock<Vec<Keypair>> =
    LazyLock::new(|| types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT));

fn get_harness(
    validator_count: usize,
    spec: Arc<ChainSpec>,
) -> BeaconChainHarness<EphemeralHarnessType<E>> {
    create_test_tracing_subscriber();
    let harness = BeaconChainHarness::builder(MainnetEthSpec)
        .spec(spec)
        .chain_config(ChainConfig {
            reconstruct_historic_states: true,
            ..ChainConfig::default()
        })
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    harness.advance_slot();

    harness
}

// Regression test for https://github.com/sigp/lighthouse/issues/7650
#[tokio::test]
async fn rpc_blobs_with_invalid_header_signature() {
    let spec = Arc::new(test_spec::<E>());

    // Only run this test if blobs are enabled and columns are disabled.
    if spec.deneb_fork_epoch.is_none() || spec.is_fulu_scheduled() {
        return;
    }

    let harness = get_harness(VALIDATOR_COUNT, spec);

    let num_blocks = E::slots_per_epoch() as usize;

    // Add some chain depth.
    harness
        .extend_chain(
            num_blocks,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Produce a block with blobs.
    harness.execution_block_generator().set_min_blob_count(1);
    let head_state = harness.get_current_state();
    let slot = head_state.slot() + 1;
    let ((signed_block, opt_blobs), _) = harness.make_block(head_state, slot).await;
    let (kzg_proofs, blobs) = opt_blobs.unwrap();
    assert!(!blobs.is_empty());
    let block_root = signed_block.canonical_root();

    // Process the block without blobs so that it doesn't become available.
    harness.advance_slot();
    let rpc_block = harness
        .build_rpc_block_from_blobs(block_root, signed_block.clone(), None)
        .unwrap();
    let availability = harness
        .chain
        .process_block(
            block_root,
            rpc_block,
            NotifyExecutionLayer::Yes,
            BlockImportSource::RangeSync,
            || Ok(()),
        )
        .await
        .unwrap();
    assert_eq!(
        availability,
        AvailabilityProcessingStatus::MissingComponents(slot, block_root)
    );

    // Build blob sidecars with invalid signatures in the block header.
    let mut corrupt_block = (*signed_block).clone();
    *corrupt_block.signature_mut() = Signature::infinity().unwrap();

    let max_len = harness
        .chain
        .spec
        .max_blobs_per_block(slot.epoch(E::slots_per_epoch())) as usize;
    let mut blob_sidecars = FixedBlobSidecarList::new(vec![None; max_len]);
    for (i, (kzg_proof, blob)) in kzg_proofs.into_iter().zip(blobs).enumerate() {
        let blob_sidecar = BlobSidecar::new(i, blob, &corrupt_block, kzg_proof).unwrap();
        blob_sidecars[i] = Some(Arc::new(blob_sidecar));
    }

    let err = harness
        .chain
        .process_rpc_blobs(slot, block_root, blob_sidecars)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        BlockError::InvalidSignature(InvalidSignature::ProposerSignature)
    ));
}
