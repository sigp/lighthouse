use crate::AvailabilityProcessingStatus;
use crate::data_column_verification::KzgVerifiedCustodyDataColumn;
use crate::fetch_blobs::fetch_blobs_beacon_adapter::MockFetchBlobsBeaconAdapter;
use crate::fetch_blobs::{
    FetchEngineBlobError, PartialHeaderOrBid, fetch_and_process_engine_blobs_inner,
};
use crate::partial_data_column_assembler::PartialDataColumnAssembler;
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
    use types::{ColumnIndex, PartialDataColumnHeader};

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
        mock_adapter.expect_process_engine_blobs_fulu().times(0);

        let custody_columns: [ColumnIndex; 3] = [0, 1, 2];
        let processing_status = fetch_and_process_engine_blobs_inner(
            mock_adapter,
            block_root,
            PartialHeaderOrBid::PartialHeader(Arc::new((&block).try_into().unwrap())),
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
            PartialHeaderOrBid::PartialHeader(Arc::new(
                PartialDataColumnHeader::try_from(block.as_ref()).unwrap(),
            )),
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
        mock_adapter.expect_process_engine_blobs_fulu().times(0);

        // Trigger fetch blobs on the block
        let custody_columns: [ColumnIndex; 3] = [0, 1, 2];
        let processing_status = fetch_and_process_engine_blobs_inner(
            mock_adapter,
            block_root,
            PartialHeaderOrBid::PartialHeader(Arc::new(
                PartialDataColumnHeader::try_from(block.as_ref()).unwrap(),
            )),
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
        mock_adapter.expect_process_engine_blobs_fulu().times(0);

        // Trigger fetch blobs on the block
        let custody_columns: [ColumnIndex; 3] = [0, 1, 2];
        let processing_status = fetch_and_process_engine_blobs_inner(
            mock_adapter,
            block_root,
            PartialHeaderOrBid::PartialHeader(Arc::new(
                PartialDataColumnHeader::try_from(block.as_ref()).unwrap(),
            )),
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
            .expect_data_column_known_for_observation_key()
            .returning(|_| Some(hashset![0, 1, 2]));
        // No blobs should be processed
        mock_adapter.expect_process_engine_blobs_fulu().times(0);

        // **WHEN**: Trigger `fetch_blobs` on the block
        let custody_columns: [ColumnIndex; 3] = [0, 1, 2];
        let processing_status = fetch_and_process_engine_blobs_inner(
            mock_adapter,
            block_root,
            PartialHeaderOrBid::PartialHeader(Arc::new(
                PartialDataColumnHeader::try_from(block.as_ref()).unwrap(),
            )),
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
            .expect_data_column_known_for_observation_key()
            .returning(|_| None);
        mock_adapter
            .expect_cached_data_column_indexes()
            .returning(|_, _| None);
        mock_process_engine_blobs_result(
            &mut mock_adapter,
            Ok(AvailabilityProcessingStatus::Imported(
                block.slot(),
                block_root,
            )),
        );

        // Trigger fetch blobs on the block
        let custody_columns: [ColumnIndex; 3] = [0, 1, 2];
        let processing_status = fetch_and_process_engine_blobs_inner(
            mock_adapter,
            block_root,
            PartialHeaderOrBid::PartialHeader(Arc::new(
                PartialDataColumnHeader::try_from(block.as_ref()).unwrap(),
            )),
            &custody_columns,
            publish_fn,
        )
        .await
        .expect("fetch blobs should succeed");

        assert_eq!(
            processing_status,
            Some(AvailabilityProcessingStatus::Imported(
                block.slot(),
                block_root
            ))
        );

        let published_columns = extract_published_blobs(publish_fn_args);
        assert!(
            matches!(
                published_columns,
                columns if columns.len() == custody_columns.len()
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

mod get_blobs_v4 {
    use super::*;
    use crate::custody_context::{CustodyContext, NodeCustodyType};
    use crate::pending_payload_cache::PendingPayloadCache;
    use crate::test_utils::{
        NumBlobs, generate_data_column_indices_rand_order, generate_rand_block_and_blobs,
    };
    use execution_layer::json_structures::{BlobCellsAndProofsV1, JsonCell};
    use kzg::KzgProof;
    use slot_clock::{SlotClock, TestingSlotClock};
    use std::time::Duration;
    use types::test_utils::test_unstructured;
    use types::{Cell, ColumnIndex, PartialDataColumnHeader, Slot};

    const CUSTODY_COLUMNS: [ColumnIndex; 3] = [0, 1, 2];

    /// Build an `engine_getBlobsV4` response for `num_blobs` blobs, with one entry per requested
    /// custody column (positionally, lowest column index first). `present(blob_idx, col_pos)`
    /// decides whether that cell/proof is present. Cell contents are irrelevant: the V4 path trusts
    /// the EL and never re-verifies the returned cells.
    fn make_v4_response(
        num_blobs: usize,
        num_custody_cols: usize,
        present: impl Fn(usize, usize) -> bool,
    ) -> Vec<Option<BlobCellsAndProofsV1<E>>> {
        (0..num_blobs)
            .map(|blob_idx| {
                let blob_cells = (0..num_custody_cols)
                    .map(|col_pos| {
                        present(blob_idx, col_pos).then(|| JsonCell(Cell::<E>::default()))
                    })
                    .collect();
                let proofs = (0..num_custody_cols)
                    .map(|col_pos| present(blob_idx, col_pos).then(KzgProof::empty))
                    .collect();
                Some(BlobCellsAndProofsV1 { blob_cells, proofs })
            })
            .collect()
    }

    fn fulu_header(block: &SignedBeaconBlock<E>) -> PartialHeaderOrBid<E> {
        PartialHeaderOrBid::PartialHeader(Arc::new(
            PartialDataColumnHeader::try_from(block).unwrap(),
        ))
    }

    /// A complete V4 response assembles into full columns that are published and imported.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_fetch_blobs_v4_fulu_success() {
        let mut mock_adapter = mock_beacon_adapter_v4(ForkName::Fulu);
        let (publish_fn, publish_fn_args) = mock_publish_fn();
        let (block, _blobs) = create_test_block_and_blobs(&mock_adapter, 2);
        let block_root = block.canonical_root();

        let response = make_v4_response(2, CUSTODY_COLUMNS.len(), |_, _| true);
        mock_adapter
            .expect_get_blobs_v4()
            .return_once(move |_, _| Ok(response));
        mock_fork_choice_contains_block(&mut mock_adapter, vec![]);
        mock_adapter
            .expect_data_column_known_for_observation_key()
            .returning(|_| None);
        mock_adapter
            .expect_cached_data_column_indexes()
            .returning(|_, _| None);
        mock_process_engine_blobs_result(
            &mut mock_adapter,
            Ok(AvailabilityProcessingStatus::Imported(
                block.slot(),
                block_root,
            )),
        );

        let processing_status = fetch_and_process_engine_blobs_inner(
            mock_adapter,
            block_root,
            fulu_header(block.as_ref()),
            &CUSTODY_COLUMNS,
            publish_fn,
        )
        .await
        .expect("fetch blobs should succeed");

        assert_eq!(
            processing_status,
            Some(AvailabilityProcessingStatus::Imported(
                block.slot(),
                block_root
            ))
        );
        assert_eq!(
            extract_published_blobs(publish_fn_args).len(),
            CUSTODY_COLUMNS.len(),
            "all custody columns should be published"
        );
    }

    /// A partial V4 response that leaves every column short of a cell yields no full columns: nothing
    /// is published or imported, and we report missing components.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_fetch_blobs_v4_fulu_partial_response_completes_nothing() {
        let mut mock_adapter = mock_beacon_adapter_v4(ForkName::Fulu);
        let (publish_fn, publish_fn_args) = mock_publish_fn();
        let (block, _blobs) = create_test_block_and_blobs(&mock_adapter, 2);
        let block_root = block.canonical_root();

        // Only the first blob's cells are present, so each column is missing blob 1's cell.
        let response = make_v4_response(2, CUSTODY_COLUMNS.len(), |blob_idx, _| blob_idx == 0);
        mock_adapter
            .expect_get_blobs_v4()
            .return_once(move |_, _| Ok(response));
        mock_fork_choice_contains_block(&mut mock_adapter, vec![]);
        mock_adapter
            .expect_data_column_known_for_observation_key()
            .returning(|_| None);
        mock_adapter
            .expect_cached_data_column_indexes()
            .returning(|_, _| None);
        mock_adapter.expect_process_engine_blobs_fulu().times(0);

        let processing_status = fetch_and_process_engine_blobs_inner(
            mock_adapter,
            block_root,
            fulu_header(block.as_ref()),
            &CUSTODY_COLUMNS,
            publish_fn,
        )
        .await
        .expect("fetch blobs should succeed");

        assert_eq!(
            processing_status,
            Some(AvailabilityProcessingStatus::MissingComponents(
                block.slot(),
                block_root
            ))
        );
        assert_eq!(
            publish_fn_args.lock().unwrap().len(),
            0,
            "no columns should be published"
        );
    }

    /// An empty (all-null) V4 response is treated as a miss: nothing imported or published.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_fetch_blobs_v4_no_cells_returned() {
        let mut mock_adapter = mock_beacon_adapter_v4(ForkName::Fulu);
        let (publish_fn, publish_fn_args) = mock_publish_fn();
        let (block, _blobs) = create_test_block_and_blobs(&mock_adapter, 2);
        let block_root = block.canonical_root();

        let response = make_v4_response(2, CUSTODY_COLUMNS.len(), |_, _| false);
        mock_adapter
            .expect_get_blobs_v4()
            .return_once(move |_, _| Ok(response));
        mock_adapter.expect_process_engine_blobs_fulu().times(0);

        let processing_status = fetch_and_process_engine_blobs_inner(
            mock_adapter,
            block_root,
            fulu_header(block.as_ref()),
            &CUSTODY_COLUMNS,
            publish_fn,
        )
        .await
        .expect("fetch blobs should succeed");

        assert_eq!(processing_status, None);
        assert_eq!(publish_fn_args.lock().unwrap().len(), 0);
    }

    /// A response whose blob count disagrees with the block's commitment count is rejected.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_fetch_blobs_v4_wrong_response_length() {
        let mut mock_adapter = mock_beacon_adapter_v4(ForkName::Fulu);
        let (publish_fn, publish_fn_args) = mock_publish_fn();
        let (block, _blobs) = create_test_block_and_blobs(&mock_adapter, 2);
        let block_root = block.canonical_root();

        // The block expects 2 blobs, but the EL returns only 1 entry.
        let response = make_v4_response(1, CUSTODY_COLUMNS.len(), |_, _| true);
        mock_adapter
            .expect_get_blobs_v4()
            .return_once(move |_, _| Ok(response));
        mock_adapter.expect_process_engine_blobs_fulu().times(0);

        let processing_status = fetch_and_process_engine_blobs_inner(
            mock_adapter,
            block_root,
            fulu_header(block.as_ref()),
            &CUSTODY_COLUMNS,
            publish_fn,
        )
        .await
        .expect("fetch blobs should succeed");

        assert_eq!(processing_status, None);
        assert_eq!(publish_fn_args.lock().unwrap().len(), 0);
    }

    /// Columns already observed on gossip are deduped away, leaving nothing to import.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_fetch_blobs_v4_all_columns_already_observed() {
        let mut mock_adapter = mock_beacon_adapter_v4(ForkName::Fulu);
        let (publish_fn, publish_fn_args) = mock_publish_fn();
        let (block, _blobs) = create_test_block_and_blobs(&mock_adapter, 2);
        let block_root = block.canonical_root();

        let response = make_v4_response(2, CUSTODY_COLUMNS.len(), |_, _| true);
        mock_adapter
            .expect_get_blobs_v4()
            .return_once(move |_, _| Ok(response));
        mock_fork_choice_contains_block(&mut mock_adapter, vec![]);
        mock_adapter
            .expect_data_column_known_for_observation_key()
            .returning(|_| Some(hashset![0, 1, 2]));
        mock_adapter
            .expect_cached_data_column_indexes()
            .returning(|_, _| None);
        mock_adapter.expect_process_engine_blobs_fulu().times(0);

        let processing_status = fetch_and_process_engine_blobs_inner(
            mock_adapter,
            block_root,
            fulu_header(block.as_ref()),
            &CUSTODY_COLUMNS,
            publish_fn,
        )
        .await
        .expect("fetch blobs should succeed");

        assert_eq!(processing_status, None);
        assert_eq!(publish_fn_args.lock().unwrap().len(), 0);
    }

    /// The Gloas (bid) path also flows through V4: a complete response merges into the pending
    /// payload cache, publishes the completed columns, and processes envelope availability. This is
    /// the regression test for the previously-missing Gloas support in the V4 path.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_fetch_blobs_v4_gloas_success() {
        let mut mock_adapter = mock_beacon_adapter_v4(ForkName::Gloas);
        let spec = mock_adapter.spec().clone();
        let (publish_fn, publish_fn_args) = mock_publish_fn();

        // A Gloas block carries its blob commitments in the execution payload bid.
        let mut u = test_unstructured();
        let (block, _blobs) =
            generate_rand_block_and_blobs::<E>(ForkName::Gloas, NumBlobs::Number(2), &mut u)
                .expect("generate gloas block");
        let block_root = block.canonical_root();
        let bid = Arc::new(
            block
                .message()
                .body()
                .signed_execution_payload_bid()
                .expect("gloas block has a bid")
                .clone(),
        );

        // Real pending payload cache: the Gloas path inserts the bid and merges partial columns into
        // it, so a mock would not exercise the actual merge/availability logic.
        let slot_clock = TestingSlotClock::new(
            Slot::new(0),
            Duration::from_secs(0),
            spec.get_slot_duration(),
        );
        let custody_context = Arc::new(CustodyContext::<T>::new(
            NodeCustodyType::Supernode,
            generate_data_column_indices_rand_order::<E>(),
            slot_clock,
            false,
            spec.clone(),
        ));
        let cache = Arc::new(
            PendingPayloadCache::<T>::new(get_kzg(&spec), custody_context, false, spec.clone())
                .expect("create pending payload cache"),
        );
        mock_adapter
            .expect_pending_payload_cache()
            .return_const(cache);

        let response = make_v4_response(2, CUSTODY_COLUMNS.len(), |_, _| true);
        mock_adapter
            .expect_get_blobs_v4()
            .return_once(move |_, _| Ok(response));
        mock_fork_choice_contains_block(&mut mock_adapter, vec![]);
        mock_adapter
            .expect_data_column_known_for_observation_key()
            .returning(|_| None);
        mock_adapter
            .expect_cached_data_column_indexes()
            .returning(|_, _| None);
        mock_adapter
            .expect_process_payload_envelope_availability()
            .return_once(move |slot, _availability| {
                Ok(AvailabilityProcessingStatus::MissingComponents(
                    slot, block_root,
                ))
            });

        let processing_status = fetch_and_process_engine_blobs_inner(
            mock_adapter,
            block_root,
            PartialHeaderOrBid::Bid(bid),
            &CUSTODY_COLUMNS,
            publish_fn,
        )
        .await
        .expect("fetch blobs should succeed");

        assert!(
            processing_status.is_some(),
            "the gloas path should return an availability status"
        );
        assert_eq!(
            extract_published_blobs(publish_fn_args).len(),
            CUSTODY_COLUMNS.len(),
            "all three custody columns should complete and be published"
        );
    }
}

/// Extract the `Vec<KzgVerifiedCustodyDataColumn<E>>` passed to the `publish_fn`.
fn extract_published_blobs(
    publish_fn_args: Arc<Mutex<Vec<Vec<KzgVerifiedCustodyDataColumn<E>>>>>,
) -> Vec<KzgVerifiedCustodyDataColumn<E>> {
    let mut calls = publish_fn_args.lock().unwrap();
    assert_eq!(calls.len(), 1);
    calls.pop().unwrap()
}

fn mock_process_engine_blobs_result(
    mock_adapter: &mut MockFetchBlobsBeaconAdapter<T>,
    result: Result<AvailabilityProcessingStatus, FetchEngineBlobError>,
) {
    mock_adapter
        .expect_process_engine_blobs_fulu()
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
                    proofs: proofs.to_vec().try_into().unwrap(),
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
    impl Fn(Vec<KzgVerifiedCustodyDataColumn<E>>) + Send + 'static,
    Arc<Mutex<Vec<Vec<KzgVerifiedCustodyDataColumn<E>>>>>,
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
    mock_beacon_adapter_with_capabilities(fork_name, false)
}

/// Like [`mock_beacon_adapter`], but advertises `engine_getBlobsV4` support so the V4 fetch path is
/// exercised instead of V2/V3.
fn mock_beacon_adapter_v4(fork_name: ForkName) -> MockFetchBlobsBeaconAdapter<T> {
    mock_beacon_adapter_with_capabilities(fork_name, true)
}

fn mock_beacon_adapter_with_capabilities(
    fork_name: ForkName,
    supports_get_blobs_v4: bool,
) -> MockFetchBlobsBeaconAdapter<T> {
    let test_runtime = TestRuntime::default();
    let spec = Arc::new(fork_name.make_genesis_spec(E::default_spec()));
    let kzg = get_kzg(&spec);
    let partial_assembler = PartialDataColumnAssembler::new(32, false);

    let mut mock_adapter = MockFetchBlobsBeaconAdapter::default();
    mock_adapter.expect_spec().return_const(spec.clone());
    mock_adapter.expect_kzg().return_const(kzg.clone());
    mock_adapter
        .expect_executor()
        .return_const(test_runtime.task_executor.clone());
    mock_adapter
        .expect_supports_get_blobs_v3()
        .returning(move || Ok(false));
    mock_adapter
        .expect_supports_get_blobs_v4()
        .returning(move || Ok(supports_get_blobs_v4));
    mock_adapter
        .expect_partial_assembler()
        .return_const(Some(Arc::new(partial_assembler)));
    mock_adapter
}
