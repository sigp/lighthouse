#![cfg(not(debug_assertions))]

use beacon_chain::custody_context::NodeCustodyType;
use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, EphemeralHarnessType,
    generate_data_column_sidecars_from_block, test_spec,
};
use beacon_chain::{
    AvailabilityProcessingStatus, BlockError, ChainConfig, InvalidSignature, NotifyExecutionLayer,
    block_verification_types::{AsBlock, LookupBlock},
};
use bls::{Keypair, Signature};
use logging::create_test_tracing_subscriber;
use std::sync::{Arc, LazyLock};
use types::*;

type E = MainnetEthSpec;

// Should ideally be divisible by 3.
const VALIDATOR_COUNT: usize = 24;

/// A cached set of keys.
static KEYPAIRS: LazyLock<Vec<Keypair>> =
    LazyLock::new(|| types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT));

fn get_harness(
    validator_count: usize,
    spec: Arc<ChainSpec>,
    node_custody_type: NodeCustodyType,
) -> BeaconChainHarness<EphemeralHarnessType<E>> {
    create_test_tracing_subscriber();
    let harness = BeaconChainHarness::builder(MainnetEthSpec)
        .spec(spec)
        .chain_config(ChainConfig {
            archive: true,
            ..ChainConfig::default()
        })
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .node_custody_type(node_custody_type)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    harness.advance_slot();

    harness
}

// Regression test for https://github.com/sigp/lighthouse/issues/7650
#[tokio::test]
async fn rpc_columns_with_invalid_header_signature() {
    let spec = Arc::new(test_spec::<E>());

    // Only run this test if columns are enabled.
    if !spec.is_fulu_scheduled() {
        return;
    }

    let harness = get_harness(VALIDATOR_COUNT, spec, NodeCustodyType::Supernode);

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
    let (_, blobs) = opt_blobs.unwrap();
    assert!(!blobs.is_empty());
    let block_root = signed_block.canonical_root();

    // Process the block without blobs so that it doesn't become available.
    harness.advance_slot();
    let availability = harness
        .chain
        .process_block(
            block_root,
            LookupBlock::new(signed_block.clone()),
            NotifyExecutionLayer::Yes,
            BlockImportSource::Lookup,
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

    let data_column_sidecars =
        generate_data_column_sidecars_from_block(&corrupt_block, &harness.chain.spec);

    let err = harness
        .chain
        .process_rpc_custody_columns(data_column_sidecars)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        BlockError::InvalidSignature(InvalidSignature::ProposerSignature)
    ));
}

// Regression test for verify_header_signature bug: it uses head_fork() which is wrong for fork blocks
#[tokio::test]
async fn verify_header_signature_fork_block_bug() {
    // Create a spec with all forks enabled at genesis except Fulu which is at epoch 1
    // This allows us to easily create the scenario where the head is at Electra
    // but we're trying to verify a block from Fulu epoch
    let mut spec = test_spec::<E>();

    // Only run this test for FORK_NAME=fulu.
    if !spec.is_fulu_scheduled() || spec.is_gloas_scheduled() {
        return;
    }

    spec.altair_fork_epoch = Some(Epoch::new(0));
    spec.bellatrix_fork_epoch = Some(Epoch::new(0));
    spec.capella_fork_epoch = Some(Epoch::new(0));
    spec.deneb_fork_epoch = Some(Epoch::new(0));
    spec.electra_fork_epoch = Some(Epoch::new(0));
    let fulu_fork_epoch = Epoch::new(1);
    spec.fulu_fork_epoch = Some(fulu_fork_epoch);

    let spec = Arc::new(spec);
    let harness = get_harness(VALIDATOR_COUNT, spec.clone(), NodeCustodyType::Supernode);
    harness.execution_block_generator().set_min_blob_count(1);

    // Add some blocks in epoch 0 (Electra)
    harness
        .extend_chain(
            E::slots_per_epoch() as usize - 1,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Verify we're still in epoch 0 (Electra)
    let pre_fork_state = harness.get_current_state();
    assert_eq!(pre_fork_state.current_epoch(), Epoch::new(0));
    assert!(matches!(pre_fork_state, BeaconState::Electra(_)));

    // Now produce a block at the first slot of epoch 1 (Fulu fork).
    // make_block will advance the state which will trigger the Electra->Fulu upgrade.
    let fork_slot = fulu_fork_epoch.start_slot(E::slots_per_epoch());
    let ((signed_block, opt_blobs), _state_root) =
        harness.make_block(pre_fork_state.clone(), fork_slot).await;
    let (_, blobs) = opt_blobs.expect("Blobs should be present");
    assert!(!blobs.is_empty(), "Block should have blobs");
    let block_root = signed_block.canonical_root();

    // Process the block WITHOUT blobs to make it unavailable.
    // The block will be accepted but won't become the head because it's not fully available.
    // This keeps the head at the pre-fork state (Electra).
    harness.advance_slot();
    let availability = harness
        .chain
        .process_block(
            block_root,
            LookupBlock::new(signed_block.clone()),
            NotifyExecutionLayer::Yes,
            BlockImportSource::Lookup,
            || Ok(()),
        )
        .await
        .expect("Block should be processed");
    assert_eq!(
        availability,
        AvailabilityProcessingStatus::MissingComponents(fork_slot, block_root),
        "Block should be pending availability"
    );

    // The head should still be in epoch 0 (Electra) because the fork block isn't available
    let current_head_state = harness.get_current_state();
    assert_eq!(current_head_state.current_epoch(), Epoch::new(0));
    assert!(matches!(current_head_state, BeaconState::Electra(_)));

    // Now try to process columns for the fork block.
    // The bug: verify_header_signature previously used head_fork() which fetched the fork from
    // the head state (still Electra fork), but the block was signed with the Fulu fork version.
    // This caused an incorrect signature verification failure.
    let data_column_sidecars =
        generate_data_column_sidecars_from_block(&signed_block, &harness.chain.spec);

    // Now that the bug is fixed, the block should import.
    let status = harness
        .chain
        .process_rpc_custody_columns(data_column_sidecars)
        .await
        .unwrap();
    assert_eq!(status, AvailabilityProcessingStatus::Imported(block_root));
}
