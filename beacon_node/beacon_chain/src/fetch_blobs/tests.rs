use crate::AvailabilityProcessingStatus;
use crate::fetch_blobs::fetch_blobs_beacon_adapter::MockFetchBlobsBeaconAdapter;
use crate::fetch_blobs::{
    EngineGetBlobsOutput, FetchEngineBlobError, fetch_and_process_engine_blobs_inner,
};
use crate::test_utils::{EphemeralHarnessType, get_kzg};
use bls::Signature;
use eth2::types::BlobsBundle;
use execution_layer::json_structures::{BlobAndProof, BlobAndProofV1, BlobAndProofV2};
use execution_layer::test_utils::generate_blobs;
use maplit::hashset;
use std::sync::{Arc, Mutex};
use task_executor::test_utils::TestRuntime;
use types::{
    BeaconBlock, BeaconBlockFulu, EmptyBlock, EthSpec, ForkName, Hash256, MainnetEthSpec,
    SignedBeaconBlock, SignedBeaconBlockFulu,
};

type E = MainnetEthSpec;
type T = EphemeralHarnessType<E>;

mod get_blobs_v2 {
    use super::*;
    use types::ColumnIndex;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_fetch_blobs_v2_no_blobs_in_block() {
        let mut mock_adapter = mock_beacon_adapter(ForkName::Fulu);
        let (publish_fn, _s) = mock_publish_fn();
        let block = SignedBeaconBlock::<E>::Fulu(SignedBeaconBlockFulu {
            message: BeaconBlockFulu::empty(mock_adapter.spec()),
            signature: Signature::empty(),
        });
        let block_root = block.canonical_root();

        // Expectations: engine fetch blobs should not be triggered
        mock_adapter.expect_get_blobs_v2().times(0);
        mock_adapter.expect_process_engine_blobs().times(0);

        let custody_columns: [ColumnIndex; 3] = [0, 1, 2];
        let processing_status = fetch_and_process_engine_blobs_inner(
            mock_adapter,
            block_root,
            Arc::new(block),
            &custody_columns,
            publish_fn,
        )
        .await
        .expect("fetch blobs should succeed");

        assert_eq!(processing_status, None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_fetch_blobs_v2_no_blobs_returned() {
        let mut mock_adapter = mock_beacon_adapter(ForkName::Fulu);
        let (publish_fn, _) = mock_publish_fn();
        let (block, _blobs_and_proofs) = create_test_block_and_blobs(&mock_adapter, 2);
        let block_root = block.canonical_root();

        // No blobs in EL response
        mock_get_blobs_v2_response(&mut mock_adapter, None);

        // Trigger fetch blobs on the block
        let custody_columns: [ColumnIndex; 3] = [0, 1, 2];
        let processing_status = fetch_and_process_engine_blobs_inner(
            mock_adapter,
            block_root,
            block,
            &custody_columns,
            publish_fn,
        )
        .await
        .expect("fetch blobs should succeed");

        assert_eq!(processing_status, None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_fetch_blobs_v2_partial_blobs_returned() {
        let mut mock_adapter = mock_beacon_adapter(ForkName::Fulu);
        let (publish_fn, publish_fn_args) = mock_publish_fn();
        let (block, mut blobs_and_proofs) = create_test_block_and_blobs(&mock_adapter, 2);
        let block_root = block.canonical_root();

        // Missing blob in EL response
        blobs_and_proofs.pop();
        mock_get_blobs_v2_response(&mut mock_adapter, Some(blobs_and_proofs));
        // No blobs should be processed
        mock_adapter.expect_process_engine_blobs().times(0);

        // Trigger fetch blobs on the block
        let custody_columns: [ColumnIndex; 3] = [0, 1, 2];
        let processing_status = fetch_and_process_engine_blobs_inner(
            mock_adapter,
            block_root,
            block,
            &custody_columns,
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
        let mut mock_adapter = mock_beacon_adapter(ForkName::Fulu);
        let (publish_fn, publish_fn_args) = mock_publish_fn();
        let (block, blobs_and_proofs) = create_test_block_and_blobs(&mock_adapter, 2);
        let block_root = block.canonical_root();

        // All blobs returned, but fork choice already imported the block
        mock_get_blobs_v2_response(&mut mock_adapter, Some(blobs_and_proofs));
        mock_fork_choice_contains_block(&mut mock_adapter, vec![block.canonical_root()]);
        // No blobs should be processed
        mock_adapter.expect_process_engine_blobs().times(0);

        // Trigger fetch blobs on the block
        let custody_columns: [ColumnIndex; 3] = [0, 1, 2];
        let processing_status = fetch_and_process_engine_blobs_inner(
            mock_adapter,
            block_root,
            block,
            &custody_columns,
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
        let mut mock_adapter = mock_beacon_adapter(ForkName::Fulu);
        let (publish_fn, publish_fn_args) = mock_publish_fn();
        let (block, blobs_and_proofs) = create_test_block_and_blobs(&mock_adapter, 2);
        let block_root = block.canonical_root();

        // **GIVEN**:
        // All blobs returned
        mock_get_blobs_v2_response(&mut mock_adapter, Some(blobs_and_proofs));
        // block not yet imported into fork choice
        mock_fork_choice_contains_block(&mut mock_adapter, vec![]);
        // All data columns already seen on gossip
        mock_adapter
            .expect_data_column_known_for_proposal()
            .returning(|_| Some(hashset![0, 1, 2]));
        // No blobs should be processed
        mock_adapter.expect_process_engine_blobs().times(0);

        // **WHEN**: Trigger `fetch_blobs` on the block
        let custody_columns: [ColumnIndex; 3] = [0, 1, 2];
        let processing_status = fetch_and_process_engine_blobs_inner(
            mock_adapter,
            block_root,
            block,
            &custody_columns,
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
        let mut mock_adapter = mock_beacon_adapter(ForkName::Fulu);
        let (publish_fn, publish_fn_args) = mock_publish_fn();
        let (block, blobs_and_proofs) = create_test_block_and_blobs(&mock_adapter, 2);
        let block_root = block.canonical_root();

        // All blobs returned, fork choice doesn't contain block
        mock_get_blobs_v2_response(&mut mock_adapter, Some(blobs_and_proofs));
        mock_fork_choice_contains_block(&mut mock_adapter, vec![]);
        mock_adapter
            .expect_data_column_known_for_proposal()
            .returning(|_| None);
        mock_adapter
            .expect_cached_data_column_indexes()
            .returning(|_| None);
        mock_process_engine_blobs_result(
            &mut mock_adapter,
            Ok(AvailabilityProcessingStatus::Imported(block_root)),
        );

        // Trigger fetch blobs on the block
        let custody_columns: [ColumnIndex; 3] = [0, 1, 2];
        let processing_status = fetch_and_process_engine_blobs_inner(
            mock_adapter,
            block_root,
            block,
            &custody_columns,
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

    fn mock_get_blobs_v2_response(
        mock_adapter: &mut MockFetchBlobsBeaconAdapter<T>,
        blobs_and_proofs_opt: Option<Vec<BlobAndProof<E>>>,
    ) {
        let blobs_and_proofs_v2_opt = blobs_and_proofs_opt.map(|blobs_and_proofs| {
            blobs_and_proofs
                .into_iter()
                .map(|blob_and_proof| match blob_and_proof {
                    BlobAndProof::V2(inner) => inner,
                    _ => panic!("BlobAndProofV2 not expected"),
                })
                .collect()
        });
        mock_adapter
            .expect_get_blobs_v2()
            .return_once(move |_| Ok(blobs_and_proofs_v2_opt));
    }
}

mod get_blobs_v1 {
    use super::*;
    use crate::block_verification_types::AsBlock;
    use std::collections::HashSet;
    use types::ColumnIndex;

    const ELECTRA_FORK: ForkName = ForkName::Electra;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_fetch_blobs_v1_no_blobs_in_block() {
        let mut mock_adapter = mock_beacon_adapter(ELECTRA_FORK);
        let spec = mock_adapter.spec();
        let (publish_fn, _s) = mock_publish_fn();
        let block_no_blobs =
            SignedBeaconBlock::from_block(BeaconBlock::empty(spec), Signature::empty());
        let block_root = block_no_blobs.canonical_root();

        // Expectations: engine fetch blobs should not be triggered
        mock_adapter.expect_get_blobs_v1().times(0);

        // WHEN: Trigger fetch blobs on the block
        let custody_columns: [ColumnIndex; 3] = [0, 1, 2];
        let processing_status = fetch_and_process_engine_blobs_inner(
            mock_adapter,
            block_root,
            Arc::new(block_no_blobs),
            &custody_columns,
            publish_fn,
        )
        .await
        .expect("fetch blobs should succeed");

        // THEN: No blob is processed
        assert_eq!(processing_status, None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_fetch_blobs_v1_no_blobs_returned() {
        let mut mock_adapter = mock_beacon_adapter(ELECTRA_FORK);
        let (publish_fn, _) = mock_publish_fn();
        let (block, _blobs_and_proofs) = create_test_block_and_blobs(&mock_adapter, 2);
        let block_root = block.canonical_root();

        // GIVEN: No blobs in EL response
        let expected_blob_count = block.message().body().blob_kzg_commitments().unwrap().len();
        mock_get_blobs_v1_response(&mut mock_adapter, vec![None; expected_blob_count]);

        // WHEN: Trigger fetch blobs on the block
        let custody_columns: [ColumnIndex; 3] = [0, 1, 2];
        let processing_status = fetch_and_process_engine_blobs_inner(
            mock_adapter,
            block_root,
            block,
            &custody_columns,
            publish_fn,
        )
        .await
        .expect("fetch blobs should succeed");

        // THEN: No blob is processed
        assert_eq!(processing_status, None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_fetch_blobs_v1_partial_blobs_returned() {
        let mut mock_adapter = mock_beacon_adapter(ELECTRA_FORK);
        let (publish_fn, publish_fn_args) = mock_publish_fn();
        let blob_count = 2;
        let (block, blobs_and_proofs) = create_test_block_and_blobs(&mock_adapter, blob_count);
        let block_slot = block.slot();
        let block_root = block.canonical_root();

        // GIVEN: Missing a blob in EL response (remove 1 blob from response)
        let mut blob_and_proof_opts = blobs_and_proofs.into_iter().map(Some).collect::<Vec<_>>();
        blob_and_proof_opts.first_mut().unwrap().take();
        mock_get_blobs_v1_response(&mut mock_adapter, blob_and_proof_opts);
        // AND block is not imported into fork choice
        mock_fork_choice_contains_block(&mut mock_adapter, vec![]);
        // AND all blobs have not yet been seen
        mock_adapter
            .expect_cached_blob_indexes()
            .returning(|_| None);
        mock_adapter
            .expect_blobs_known_for_proposal()
            .returning(|_, _| None);
        // Returned blobs should be processed
        mock_process_engine_blobs_result(
            &mut mock_adapter,
            Ok(AvailabilityProcessingStatus::MissingComponents(
                block_slot, block_root,
            )),
        );

        // WHEN: Trigger fetch blobs on the block
        let custody_columns: [ColumnIndex; 3] = [0, 1, 2];
        let processing_status = fetch_and_process_engine_blobs_inner(
            mock_adapter,
            block_root,
            block,
            &custody_columns,
            publish_fn,
        )
        .await
        .expect("fetch blobs should succeed");

        // THEN: Returned blobs are processed and published
        assert_eq!(
            processing_status,
            Some(AvailabilityProcessingStatus::MissingComponents(
                block_slot, block_root,
            ))
        );
        assert!(
            matches!(
                extract_published_blobs(publish_fn_args),
                EngineGetBlobsOutput::Blobs(blobs) if blobs.len() == blob_count - 1
            ),
            "partial blob results should still be published"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_fetch_blobs_v1_block_imported_after_el_response() {
        let mut mock_adapter = mock_beacon_adapter(ELECTRA_FORK);
        let (publish_fn, publish_fn_args) = mock_publish_fn();
        let (block, blobs_and_proofs) = create_test_block_and_blobs(&mock_adapter, 2);
        let block_root = block.canonical_root();

        // GIVEN: All blobs returned, but fork choice already imported the block
        let blob_and_proof_opts = blobs_and_proofs.into_iter().map(Some).collect::<Vec<_>>();
        mock_get_blobs_v1_response(&mut mock_adapter, blob_and_proof_opts);
        mock_fork_choice_contains_block(&mut mock_adapter, vec![block.canonical_root()]);

        // WHEN: Trigger fetch blobs on the block
        let custody_columns: [ColumnIndex; 3] = [0, 1, 2];
        let processing_status = fetch_and_process_engine_blobs_inner(
            mock_adapter,
            block_root,
            block,
            &custody_columns,
            publish_fn,
        )
        .await
        .expect("fetch blobs should succeed");

        // THEN: Returned blobs should NOT be processed or published.
        assert_eq!(processing_status, None);
        assert_eq!(
            publish_fn_args.lock().unwrap().len(),
            0,
            "no blobs should be published"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_fetch_blobs_v1_no_new_blobs_to_import() {
        let mut mock_adapter = mock_beacon_adapter(ELECTRA_FORK);
        let (publish_fn, publish_fn_args) = mock_publish_fn();
        let (block, blobs_and_proofs) = create_test_block_and_blobs(&mock_adapter, 2);
        let block_root = block.canonical_root();

        // **GIVEN**:
        // All blobs returned
        let blob_and_proof_opts = blobs_and_proofs.into_iter().map(Some).collect::<Vec<_>>();
        let all_blob_indices = blob_and_proof_opts
            .iter()
            .enumerate()
            .map(|(i, _)| i as u64)
            .collect::<HashSet<_>>();

        mock_get_blobs_v1_response(&mut mock_adapter, blob_and_proof_opts);
        // block not yet imported into fork choice
        mock_fork_choice_contains_block(&mut mock_adapter, vec![]);
        // All blobs already seen on gossip
        mock_adapter
            .expect_cached_blob_indexes()
            .returning(|_| None);
        mock_adapter
            .expect_blobs_known_for_proposal()
            .returning(move |_, _| Some(all_blob_indices.clone()));

        // **WHEN**: Trigger `fetch_blobs` on the block
        let custody_columns: [ColumnIndex; 3] = [0, 1, 2];
        let processing_status = fetch_and_process_engine_blobs_inner(
            mock_adapter,
            block_root,
            block,
            &custody_columns,
            publish_fn,
        )
        .await
        .expect("fetch blobs should succeed");

        // **THEN**: Should NOT be processed and no blobs should be published.
        assert_eq!(processing_status, None);
        assert_eq!(
            publish_fn_args.lock().unwrap().len(),
            0,
            "no blobs should be published"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_fetch_blobs_v1_success() {
        let mut mock_adapter = mock_beacon_adapter(ELECTRA_FORK);
        let (publish_fn, publish_fn_args) = mock_publish_fn();
        let blob_count = 2;
        let (block, blobs_and_proofs) = create_test_block_and_blobs(&mock_adapter, blob_count);
        let block_root = block.canonical_root();

        // All blobs returned, fork choice doesn't contain block
        let blob_and_proof_opts = blobs_and_proofs.into_iter().map(Some).collect::<Vec<_>>();
        mock_get_blobs_v1_response(&mut mock_adapter, blob_and_proof_opts);
        mock_fork_choice_contains_block(&mut mock_adapter, vec![]);
        mock_adapter
            .expect_cached_blob_indexes()
            .returning(|_| None);
        mock_adapter
            .expect_blobs_known_for_proposal()
            .returning(|_, _| None);
        mock_process_engine_blobs_result(
            &mut mock_adapter,
            Ok(AvailabilityProcessingStatus::Imported(block_root)),
        );

        // Trigger fetch blobs on the block
        let custody_columns: [ColumnIndex; 3] = [0, 1, 2];
        let processing_status = fetch_and_process_engine_blobs_inner(
            mock_adapter,
            block_root,
            block,
            &custody_columns,
            publish_fn,
        )
        .await
        .expect("fetch blobs should succeed");

        // THEN all fetched blobs are processed and published
        assert_eq!(
            processing_status,
            Some(AvailabilityProcessingStatus::Imported(block_root))
        );

        let published_blobs = extract_published_blobs(publish_fn_args);
        assert!(
            matches!(
                published_blobs,
                EngineGetBlobsOutput::Blobs(blobs) if blobs.len() == blob_count
            ),
            "should publish fetched blobs"
        );
    }

    fn mock_get_blobs_v1_response(
        mock_adapter: &mut MockFetchBlobsBeaconAdapter<T>,
        blobs_and_proofs_opt: Vec<Option<BlobAndProof<E>>>,
    ) {
        let blobs_and_proofs_v1 = blobs_and_proofs_opt
            .into_iter()
            .map(|blob_and_proof_opt| {
                blob_and_proof_opt.map(|blob_and_proof| match blob_and_proof {
                    BlobAndProof::V1(inner) => inner,
                    _ => panic!("BlobAndProofV1 not expected"),
                })
            })
            .collect();
        mock_adapter
            .expect_get_blobs_v1()
            .return_once(move |_| Ok(blobs_and_proofs_v1));
    }
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

fn create_test_block_and_blobs(
    mock_adapter: &MockFetchBlobsBeaconAdapter<T>,
    blob_count: usize,
) -> (Arc<SignedBeaconBlock<E>>, Vec<BlobAndProof<E>>) {
    let mut block =
        SignedBeaconBlock::from_block(BeaconBlock::empty(mock_adapter.spec()), Signature::empty());
    let fork = block.fork_name_unchecked();
    let (blobs_bundle, _tx) = generate_blobs::<E>(blob_count, fork).unwrap();
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

    let blobs_and_proofs = if fork.fulu_enabled() {
        let proofs_len = proofs.len() / blobs.len();
        blobs
            .into_iter()
            .zip(proofs.chunks(proofs_len))
            .map(|(blob, proofs)| {
                BlobAndProof::V2(BlobAndProofV2 {
                    blob,
                    proofs: proofs.to_vec().into(),
                })
            })
            .collect()
    } else {
        blobs
            .into_iter()
            .zip(proofs)
            .map(|(blob, proof)| BlobAndProof::V1(BlobAndProofV1 { blob, proof }))
            .collect()
    };

    (Arc::new(block), blobs_and_proofs)
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

fn mock_beacon_adapter(fork_name: ForkName) -> MockFetchBlobsBeaconAdapter<T> {
    let test_runtime = TestRuntime::default();
    let spec = Arc::new(fork_name.make_genesis_spec(E::default_spec()));
    let kzg = get_kzg(&spec);

    let mut mock_adapter = MockFetchBlobsBeaconAdapter::default();
    mock_adapter.expect_spec().return_const(spec.clone());
    mock_adapter.expect_kzg().return_const(kzg.clone());
    mock_adapter
        .expect_executor()
        .return_const(test_runtime.task_executor.clone());
    mock_adapter
}
