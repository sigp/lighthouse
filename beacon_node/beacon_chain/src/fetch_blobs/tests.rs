use crate::data_column_verification::{GossipDataColumnError, GossipVerifiedDataColumn};
use crate::fetch_blobs::fetch_blobs_beacon_adapter::MockFetchBlobsBeaconAdapter;
use crate::fetch_blobs::{
    fetch_and_process_engine_blobs_inner, EngineGetBlobsOutput, FetchEngineBlobError,
};
use crate::test_utils::{get_kzg, EphemeralHarnessType};
use crate::AvailabilityProcessingStatus;
use bls::Signature;
use eth2::types::BlobsBundle;
use execution_layer::json_structures::BlobAndProofV2;
use execution_layer::test_utils::generate_blobs;
use maplit::hashset;
use std::sync::{Arc, Mutex};
use task_executor::test_utils::TestRuntime;
use types::{
    BeaconBlockFulu, EmptyBlock, EthSpec, ForkName, Hash256, MainnetEthSpec, SignedBeaconBlock,
    SignedBeaconBlockFulu,
};

type E = MainnetEthSpec;
type T = EphemeralHarnessType<E>;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_fetch_blobs_v2_no_blobs_in_block() {
    let mut mock_adapter = mock_beacon_adapter();
    let (publish_fn, _s) = mock_publish_fn();
    let block = SignedBeaconBlock::<E>::Fulu(SignedBeaconBlockFulu {
        message: BeaconBlockFulu::empty(mock_adapter.spec()),
        signature: Signature::empty(),
    });
    let block_root = block.canonical_root();

    // Expectations: engine fetch blobs should not be triggered
    mock_adapter.expect_get_blobs_v2().times(0);
    mock_adapter.expect_process_engine_blobs().times(0);

    let custody_columns = hashset![0, 1, 2];
    let processing_status = fetch_and_process_engine_blobs_inner(
        mock_adapter,
        block_root,
        Arc::new(block),
        custody_columns.clone(),
        publish_fn,
    )
    .await
    .expect("fetch blobs should succeed");

    assert_eq!(processing_status, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_fetch_blobs_v2_no_blobs_returned() {
    let mut mock_adapter = mock_beacon_adapter();
    let (publish_fn, _) = mock_publish_fn();
    let (block, _blobs_and_proofs) = create_test_block_and_blobs(&mock_adapter);
    let block_root = block.canonical_root();

    // No blobs in EL response
    mock_get_blobs_v2_response(&mut mock_adapter, None);

    // Trigger fetch blobs on the block
    let custody_columns = hashset![0, 1, 2];
    let processing_status = fetch_and_process_engine_blobs_inner(
        mock_adapter,
        block_root,
        block,
        custody_columns.clone(),
        publish_fn,
    )
    .await
    .expect("fetch blobs should succeed");

    assert_eq!(processing_status, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_fetch_blobs_v2_partial_blobs_returned() {
    let mut mock_adapter = mock_beacon_adapter();
    let (publish_fn, publish_fn_args) = mock_publish_fn();
    let (block, mut blobs_and_proofs) = create_test_block_and_blobs(&mock_adapter);
    let block_root = block.canonical_root();

    // Missing blob in EL response
    blobs_and_proofs.pop();
    mock_get_blobs_v2_response(&mut mock_adapter, Some(blobs_and_proofs));
    // No blobs should be processed
    mock_adapter.expect_process_engine_blobs().times(0);

    // Trigger fetch blobs on the block
    let custody_columns = hashset![0, 1, 2];
    let processing_status = fetch_and_process_engine_blobs_inner(
        mock_adapter,
        block_root,
        block,
        custody_columns.clone(),
        publish_fn,
    )
    .await
    .expect("fetch blobs should succeed");

    assert_eq!(processing_status, None);
    assert_eq!(
        publish_fn_args.lock().unwrap().len(),
        0,
        "no columns should be published"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_fetch_blobs_v2_block_imported_after_el_response() {
    let mut mock_adapter = mock_beacon_adapter();
    let (publish_fn, publish_fn_args) = mock_publish_fn();
    let (block, blobs_and_proofs) = create_test_block_and_blobs(&mock_adapter);
    let block_root = block.canonical_root();

    // All blobs returned, but fork choice already imported the block
    mock_get_blobs_v2_response(&mut mock_adapter, Some(blobs_and_proofs));
    mock_fork_choice_contains_block(&mut mock_adapter, vec![block.canonical_root()]);
    // No blobs should be processed
    mock_adapter.expect_process_engine_blobs().times(0);

    // Trigger fetch blobs on the block
    let custody_columns = hashset![0, 1, 2];
    let processing_status = fetch_and_process_engine_blobs_inner(
        mock_adapter,
        block_root,
        block,
        custody_columns.clone(),
        publish_fn,
    )
    .await
    .expect("fetch blobs should succeed");

    assert_eq!(processing_status, None);
    assert_eq!(
        publish_fn_args.lock().unwrap().len(),
        0,
        "no columns should be published"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_fetch_blobs_v2_no_new_columns_to_import() {
    let mut mock_adapter = mock_beacon_adapter();
    let (publish_fn, publish_fn_args) = mock_publish_fn();
    let (block, blobs_and_proofs) = create_test_block_and_blobs(&mock_adapter);
    let block_root = block.canonical_root();

    // **GIVEN**:
    // All blobs returned
    mock_get_blobs_v2_response(&mut mock_adapter, Some(blobs_and_proofs));
    // block not yet imported into fork choice
    mock_fork_choice_contains_block(&mut mock_adapter, vec![]);
    // All data columns already seen on gossip
    mock_adapter
        .expect_verify_data_column_for_gossip()
        .returning(|c| {
            Err(GossipDataColumnError::PriorKnown {
                proposer: c.block_proposer_index(),
                slot: c.slot(),
                index: c.index,
            })
        });
    // No blobs should be processed
    mock_adapter.expect_process_engine_blobs().times(0);

    // **WHEN**: Trigger `fetch_blobs` on the block
    let custody_columns = hashset![0, 1, 2];
    let processing_status = fetch_and_process_engine_blobs_inner(
        mock_adapter,
        block_root,
        block,
        custody_columns.clone(),
        publish_fn,
    )
    .await
    .expect("fetch blobs should succeed");

    // **THEN**: Should NOT be processed and no columns should be published.
    assert_eq!(processing_status, None);
    assert_eq!(
        publish_fn_args.lock().unwrap().len(),
        0,
        "no columns should be published"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_fetch_blobs_v2_success() {
    let mut mock_adapter = mock_beacon_adapter();
    let (publish_fn, publish_fn_args) = mock_publish_fn();
    let (block, blobs_and_proofs) = create_test_block_and_blobs(&mock_adapter);
    let block_root = block.canonical_root();

    // All blobs returned, fork choice doesn't contain block
    mock_get_blobs_v2_response(&mut mock_adapter, Some(blobs_and_proofs));
    mock_fork_choice_contains_block(&mut mock_adapter, vec![]);
    mock_adapter
        .expect_verify_data_column_for_gossip()
        .returning(|c| Ok(GossipVerifiedDataColumn::__new_for_testing(c)));
    mock_process_engine_blobs_result(
        &mut mock_adapter,
        Ok(AvailabilityProcessingStatus::Imported(block_root)),
    );

    // Trigger fetch blobs on the block
    let custody_columns = hashset![0, 1, 2];
    let processing_status = fetch_and_process_engine_blobs_inner(
        mock_adapter,
        block_root,
        block,
        custody_columns.clone(),
        publish_fn,
    )
    .await
    .expect("fetch blobs should succeed");

    assert_eq!(
        processing_status,
        Some(AvailabilityProcessingStatus::Imported(block_root))
    );

    let published_columns = extract_published_blobs(publish_fn_args);
    assert!(
        matches!(
            published_columns,
            EngineGetBlobsOutput::CustodyColumns(columns) if columns.len() == custody_columns.len()
        ),
        "should publish custody columns"
    );
}

/// Extract the `EngineGetBlobsOutput` passed to the `publish_fn`.
fn extract_published_blobs(
    publish_fn_args: Arc<Mutex<Vec<EngineGetBlobsOutput<T>>>>,
) -> EngineGetBlobsOutput<T> {
    let mut calls = publish_fn_args.lock().unwrap();
    assert_eq!(calls.len(), 1);
    calls.pop().unwrap()
}

fn mock_process_engine_blobs_result(
    mock_adapter: &mut MockFetchBlobsBeaconAdapter<T>,
    result: Result<AvailabilityProcessingStatus, FetchEngineBlobError>,
) {
    mock_adapter
        .expect_process_engine_blobs()
        .return_once(move |_, _, _| result);
}

fn mock_fork_choice_contains_block(
    mock_adapter: &mut MockFetchBlobsBeaconAdapter<T>,
    block_roots: Vec<Hash256>,
) {
    mock_adapter
        .expect_fork_choice_contains_block()
        .returning(move |block_root| block_roots.contains(block_root));
}

fn mock_get_blobs_v2_response(
    mock_adapter: &mut MockFetchBlobsBeaconAdapter<T>,
    blobs_and_proofs_opt: Option<Vec<BlobAndProofV2<E>>>,
) {
    mock_adapter
        .expect_get_blobs_v2()
        .return_once(move |_| Ok(blobs_and_proofs_opt));
}

fn create_test_block_and_blobs(
    mock_adapter: &MockFetchBlobsBeaconAdapter<T>,
) -> (Arc<SignedBeaconBlock<E>>, Vec<BlobAndProofV2<E>>) {
    let mut block = SignedBeaconBlock::Fulu(SignedBeaconBlockFulu {
        message: BeaconBlockFulu::empty(mock_adapter.spec()),
        signature: Signature::empty(),
    });
    let (blobs_bundle, _tx) = generate_blobs::<E>(2, block.fork_name_unchecked()).unwrap();
    let BlobsBundle {
        commitments,
        proofs,
        blobs,
    } = blobs_bundle;

    *block
        .message_mut()
        .body_mut()
        .blob_kzg_commitments_mut()
        .unwrap() = commitments;

    let proofs_len = proofs.len() / blobs.len();
    let blob_and_proofs: Vec<BlobAndProofV2<E>> = blobs
        .into_iter()
        .zip(proofs.chunks(proofs_len))
        .map(|(blob, proofs)| BlobAndProofV2 {
            blob,
            proofs: proofs.to_vec().into(),
        })
        .collect();
    (Arc::new(block), blob_and_proofs)
}

#[allow(clippy::type_complexity)]
fn mock_publish_fn() -> (
    impl Fn(EngineGetBlobsOutput<T>) + Send + 'static,
    Arc<Mutex<Vec<EngineGetBlobsOutput<T>>>>,
) {
    // Keep track of the arguments captured by `publish_fn`.
    let captured_args = Arc::new(Mutex::new(vec![]));
    let captured_args_clone = captured_args.clone();
    let publish_fn = move |args| {
        let mut lock = captured_args_clone.lock().unwrap();
        lock.push(args);
    };
    (publish_fn, captured_args)
}

fn mock_beacon_adapter() -> MockFetchBlobsBeaconAdapter<T> {
    let test_runtime = TestRuntime::default();
    let spec = Arc::new(ForkName::Fulu.make_genesis_spec(E::default_spec()));
    let kzg = get_kzg(&spec);

    let mut mock_adapter = MockFetchBlobsBeaconAdapter::default();
    mock_adapter.expect_spec().return_const(spec.clone());
    mock_adapter.expect_kzg().return_const(kzg.clone());
    mock_adapter
        .expect_executor()
        .return_const(test_runtime.task_executor.clone());
    mock_adapter
}
