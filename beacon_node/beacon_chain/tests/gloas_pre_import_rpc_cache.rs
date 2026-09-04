//! Regression tests for https://github.com/sigp/lighthouse/issues/9975

#![cfg(not(debug_assertions))]

use beacon_chain::block_verification_types::LookupBlock;
use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
use beacon_chain::{AvailabilityProcessingStatus, BlockProcessStatus, NotifyExecutionLayer};
use bls::Keypair;
use futures::StreamExt;
use logging::create_test_tracing_subscriber;
use std::sync::{Arc, LazyLock};
use types::{EthSpec, ForkName, MainnetEthSpec, block::BlockImportSource};

type E = MainnetEthSpec;

// >= 32 validators required for Gloas genesis with MainnetEthSpec (32 slots/epoch).
const VALIDATOR_COUNT: usize = 32;

/// A cached set of keys.
static KEYPAIRS: LazyLock<Vec<Keypair>> =
    LazyLock::new(|| types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT));

fn gloas_harness() -> BeaconChainHarness<EphemeralHarnessType<E>> {
    create_test_tracing_subscriber();
    let spec = ForkName::Gloas.make_genesis_spec(E::default_spec());
    BeaconChainHarness::builder(MainnetEthSpec)
        .spec(Arc::new(spec))
        .keypairs(KEYPAIRS[..].to_vec())
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build()
}

#[tokio::test]
async fn gloas_pre_import_cache_serves_block_before_store_import() {
    let harness = gloas_harness();
    harness.advance_slot();

    let head_state = harness.get_current_state();
    let slot = head_state.slot() + 1;
    let ((signed_block, _), _) = harness.make_block(head_state, slot).await;
    let block_root = signed_block.canonical_root();

    harness
        .chain
        .data_availability_checker
        .put_pre_execution_block(block_root, signed_block.clone(), BlockImportSource::Gossip)
        .expect("should put pre-execution block");

    match harness.chain.get_block_process_status(&block_root) {
        BlockProcessStatus::NotValidated(cached_block, _) => {
            assert_eq!(cached_block.canonical_root(), block_root);
        }
        BlockProcessStatus::ExecutionValidated(_) => {
            panic!("expected NotValidated pre-execution status")
        }
        BlockProcessStatus::Unknown => panic!("block missing from pre-import cache"),
    }

    assert!(!harness.chain.block_is_known_to_fork_choice(&block_root));

    let mut stream = harness
        .chain
        .get_blocks_checking_caches(vec![block_root])
        .expect("should create blocks-by-root stream");
    let (root, result) = stream.next().await.expect("stream should yield one result");
    assert_eq!(root, block_root);
    let served = result
        .as_ref()
        .as_ref()
        .expect("cache lookup should succeed")
        .as_ref()
        .expect("pre-import cache should serve the block");
    assert_eq!(served.canonical_root(), block_root);
}

#[tokio::test]
async fn gloas_process_block_imports_without_custody_columns() {
    let harness = gloas_harness();
    harness.advance_slot();

    let head_state = harness.get_current_state();
    let slot = head_state.slot() + 1;
    let ((signed_block, _), _) = harness.make_block(head_state, slot).await;
    let block_root = signed_block.canonical_root();

    assert!(matches!(
        harness.chain.get_block_process_status(&block_root),
        BlockProcessStatus::Unknown
    ));

    let status = harness
        .chain
        .process_block(
            block_root,
            LookupBlock::new(signed_block),
            NotifyExecutionLayer::Yes,
            BlockImportSource::Lookup,
            || Ok(()),
        )
        .await
        .expect("gloas block should import without custody columns");

    assert!(matches!(
        status,
        AvailabilityProcessingStatus::Imported(_, imported_root) if imported_root == block_root
    ));
    assert!(harness.chain.block_is_known_to_fork_choice(&block_root));

    match harness.chain.get_block_process_status(&block_root) {
        BlockProcessStatus::NotValidated(cached_block, _)
        | BlockProcessStatus::ExecutionValidated(cached_block) => {
            assert_eq!(cached_block.canonical_root(), block_root);
        }
        BlockProcessStatus::Unknown => {
            panic!("process_block should insert the block into the pre-import cache")
        }
    }
}
