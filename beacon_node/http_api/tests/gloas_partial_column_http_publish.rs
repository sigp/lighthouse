//! Regression tests for HTTP publish + partial columns (#10104).
//!
//! With partial columns enabled, publishing a Gloas builder block without sidecars
//! must emit custody request placeholders. With them disabled, it must not.

use beacon_chain::chain_config::ChainConfig;
use beacon_chain::custody_context::NodeCustodyType;
use beacon_chain::test_utils::{AttestationStrategy, BlockStrategy, test_spec};
use eth2::types::BroadcastValidation;
use http_api::test_utils::InteractiveTester;
use http_api::{ProvenancedBlock, publish_block};
use lighthouse_network::PubsubPartialMessage;
use network::NetworkMessage;
use reqwest::StatusCode;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use types::{ColumnIndex, EthSpec, Hash256, MainnetEthSpec, SignedBeaconBlock, Slot};

type E = MainnetEthSpec;

struct HttpPublishFixture {
    tester: InteractiveTester<E>,
    block: Arc<SignedBeaconBlock<E>>,
    commitments: usize,
}

async fn setup_gloas_builder_block_without_blobs(
    enable_partial_columns: bool,
) -> Option<HttpPublishFixture> {
    let spec = test_spec::<E>();
    if spec.gloas_fork_epoch.is_none() {
        return None;
    }

    let chain_config = ChainConfig {
        enable_partial_columns,
        ..ChainConfig::default()
    };
    let tester = InteractiveTester::<E>::new_with_initializer_and_mutator(
        Some(spec),
        64,
        None,
        Some(Box::new(move |builder| builder.chain_config(chain_config))),
        Default::default(),
        false,
        NodeCustodyType::Fullnode,
    )
    .await;

    assert_eq!(
        tester.harness.chain.config.enable_partial_columns,
        enable_partial_columns
    );

    tester
        .harness
        .execution_block_generator()
        .set_min_blob_count(1);

    let num_initial: u64 = 31;
    tester.harness.advance_slot();
    tester
        .harness
        .extend_chain(
            num_initial as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;
    tester.harness.advance_slot();

    let slot = Slot::new(num_initial) + 1;
    let state = tester.harness.get_current_state();
    let ((block, blobs), _) = tester.harness.make_block(state, slot).await;

    assert!(
        blobs.is_none(),
        "precondition: Gloas make_block returns no blobs in the HTTP request"
    );
    let commitments = block
        .message()
        .body()
        .signed_execution_payload_bid()
        .expect("Gloas block must carry a payload bid")
        .message
        .blob_kzg_commitments
        .len();
    assert!(commitments > 0, "precondition: bid has blob commitments");

    Some(HttpPublishFixture {
        tester,
        block,
        commitments,
    })
}

async fn collect_partial_column_messages(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<NetworkMessage<E>>,
    timeout: Duration,
) -> Vec<PubsubPartialMessage<E>> {
    let mut messages = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(NetworkMessage::PublishPartialColumns { messages: batch })) => {
                messages.extend(batch)
            }
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => break,
        }
    }
    messages
}

fn assert_gloas_request_all_placeholders(
    messages: &[PubsubPartialMessage<E>],
    sampling_indices: &[ColumnIndex],
    block_root: Hash256,
    commitments_len: usize,
) {
    assert_eq!(
        messages.len(),
        sampling_indices.len(),
        "expected one placeholder per custody/sampling column"
    );

    let expected_indices: HashSet<_> = sampling_indices.iter().copied().collect();
    let mut actual_indices = HashSet::new();

    for message in messages {
        match message {
            PubsubPartialMessage::DataColumnGloas {
                column,
                request_cells,
            } => {
                assert_eq!(column.block_root, block_root);
                assert!(
                    column.sidecar.column.is_empty(),
                    "request-all placeholder must carry no cells"
                );
                assert!(
                    column.sidecar.kzg_proofs.is_empty(),
                    "request-all placeholder must carry no proofs"
                );
                assert_eq!(
                    column.sidecar.cells_present_bitmap.num_set_bits(),
                    0,
                    "request-all placeholder must advertise no present cells"
                );
                assert_eq!(
                    request_cells.num_set_bits(),
                    commitments_len,
                    "request-all placeholder must request every commitment cell"
                );
                assert!(
                    actual_indices.insert(column.index),
                    "duplicate custody column index {}",
                    column.index
                );
            }
            PubsubPartialMessage::DataColumnFulu { .. } => {
                panic!("Gloas HTTP publish must emit DataColumnGloas partials, not Fulu");
            }
        }
    }

    assert_eq!(
        actual_indices, expected_indices,
        "placeholder indices must match sampling columns"
    );
}

/// Ensure HTTP publish without blobs emits custody request placeholders when partial
/// columns are enabled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_publish_gloas_builder_block_without_blobs_publishes_partial_column_requests() {
    let Some(HttpPublishFixture {
        tester,
        block,
        commitments,
    }) = setup_gloas_builder_block_without_blobs(true).await
    else {
        return;
    };

    let (network_tx, mut network_rx) = tokio::sync::mpsc::unbounded_channel();

    let publication_result = publish_block(
        None,
        ProvenancedBlock::builder(block.clone(), None),
        tester.harness.chain.clone(),
        &network_tx,
        BroadcastValidation::Gossip,
        StatusCode::ACCEPTED,
        None,
    )
    .await;

    assert!(
        publication_result.is_ok(),
        "HTTP publish should succeed: {publication_result:?}"
    );
    assert!(
        tester
            .harness
            .chain
            .block_is_known_to_fork_choice(&block.canonical_root())
    );

    let messages = collect_partial_column_messages(&mut network_rx, Duration::from_secs(2)).await;
    assert!(
        !messages.is_empty(),
        "HTTP publish without blobs must emit PublishPartialColumns (#10104)"
    );

    let epoch = block.slot().epoch(E::slots_per_epoch());
    let sampling_indices = tester
        .harness
        .chain
        .custody_context
        .sampling_columns_for_epoch(epoch);
    assert_gloas_request_all_placeholders(
        &messages,
        sampling_indices,
        block.canonical_root(),
        commitments,
    );
}

/// Ensure HTTP publish does not emit partial-column requests when the feature is disabled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_publish_gloas_builder_block_partial_columns_disabled_publishes_nothing() {
    let Some(HttpPublishFixture {
        tester,
        block,
        commitments: _,
    }) = setup_gloas_builder_block_without_blobs(false).await
    else {
        return;
    };

    let (network_tx, mut network_rx) = tokio::sync::mpsc::unbounded_channel();

    let publication_result = publish_block(
        None,
        ProvenancedBlock::builder(block.clone(), None),
        tester.harness.chain.clone(),
        &network_tx,
        BroadcastValidation::Gossip,
        StatusCode::ACCEPTED,
        None,
    )
    .await;

    assert!(
        publication_result.is_ok(),
        "HTTP publish should succeed: {publication_result:?}"
    );

    let messages = collect_partial_column_messages(&mut network_rx, Duration::from_secs(2)).await;
    assert!(
        messages.is_empty(),
        "partial columns disabled must not emit PublishPartialColumns"
    );
}
