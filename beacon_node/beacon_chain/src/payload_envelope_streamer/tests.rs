use super::*;
use crate::beacon_chain::ForkChoiceError;
use crate::payload_envelope_streamer::beacon_chain_adapter::MockEnvelopeStreamerBeaconAdapter;
use crate::test_utils::EphemeralHarnessType;
use bls::{FixedBytesExtended, Signature};
use execution_layer::ExecutionPayloadBodyV2;
use futures::StreamExt;
use std::collections::HashMap;
use task_executor::test_utils::TestRuntime;
use types::{
    BlockAccessList, ExecutionBlockHash, ExecutionPayloadEnvelope, ExecutionPayloadGloas,
    ExecutionPayloadRef, ExecutionRequestsGloas, ExecutionRequestsRef, Hash256, MinimalEthSpec,
    SignedExecutionPayloadEnvelope, SignedExecutionPayloadEnvelopeSummary, Slot,
};

type E = MinimalEthSpec;
type T = EphemeralHarnessType<E>;

struct SlotEntry {
    block_root: Hash256,
    slot: Slot,
    envelope: Option<SignedExecutionPayloadEnvelope<E>>,
    non_canonical_envelope: bool,
}

impl SlotEntry {
    fn expect_envelope(&self, split_slot: Option<Slot>) -> bool {
        if self.envelope.is_none() {
            return false;
        }
        if !self.non_canonical_envelope {
            return true;
        }
        // Non-canonical envelopes before the split slot are returned
        // (in production they would have been pruned).
        split_slot.is_some_and(|s| self.slot < s)
    }
}

fn roots(chain: &[SlotEntry]) -> Vec<Hash256> {
    chain.iter().map(|s| s.block_root).collect()
}

/// Build test chain data.
fn build_chain(
    num_slots: u64,
    skipped_slots: &[u64],
    missing_envelope_slots: &[u64],
    non_canonical_envelope_slots: &[u64],
) -> Vec<SlotEntry> {
    let mut chain = Vec::new();
    for i in 1..=num_slots {
        if skipped_slots.contains(&i) {
            continue;
        }
        let slot = Slot::new(i);
        let block_root = Hash256::from_low_u64_be(i);
        let has_envelope = !missing_envelope_slots.contains(&i);
        let is_non_canonical = non_canonical_envelope_slots.contains(&i);

        let envelope = if has_envelope {
            let execution_requests = ExecutionRequestsGloas::default();
            let mut payload = ExecutionPayloadGloas {
                parent_hash: if is_non_canonical {
                    ExecutionBlockHash::from_root(Hash256::repeat_byte(0xFF))
                } else {
                    ExecutionBlockHash::default()
                },
                slot_number: slot,
                ..Default::default()
            };
            payload.block_hash = execution_layer::calculate_execution_block_hash(
                ExecutionPayloadRef::Gloas(&payload),
                Some(Hash256::ZERO),
                Some(ExecutionRequestsRef::Gloas(&execution_requests)),
            )
            .0;
            Some(SignedExecutionPayloadEnvelope {
                message: ExecutionPayloadEnvelope {
                    payload,
                    execution_requests,
                    builder_index: 0,
                    beacon_block_root: block_root,
                    parent_beacon_block_root: Hash256::ZERO,
                },
                signature: Signature::empty(),
            })
        } else {
            None
        };

        chain.push(SlotEntry {
            block_root,
            slot,
            envelope,
            non_canonical_envelope: is_non_canonical,
        });
    }
    chain
}

fn mock_adapter() -> (MockEnvelopeStreamerBeaconAdapter<T>, TestRuntime) {
    let runtime = TestRuntime::default();
    let mut mock = MockEnvelopeStreamerBeaconAdapter::default();
    mock.expect_executor()
        .return_const(runtime.task_executor.clone());
    (mock, runtime)
}

/// Configure the summary and locally retained payload reads from chain data.
fn mock_envelopes(mock: &mut MockEnvelopeStreamerBeaconAdapter<T>, chain: &[SlotEntry]) {
    mock_envelopes_with_pruned_payloads(mock, chain, &[]);
}

fn mock_envelopes_with_pruned_payloads(
    mock: &mut MockEnvelopeStreamerBeaconAdapter<T>,
    chain: &[SlotEntry],
    pruned_payload_slots: &[u64],
) {
    let summary_map: HashMap<Hash256, Option<SignedExecutionPayloadEnvelopeSummary<E>>> = chain
        .iter()
        .map(|entry| {
            let summary = entry
                .envelope
                .clone()
                .map(|envelope| <(_, _)>::from(envelope).0);
            (entry.block_root, summary)
        })
        .collect();
    mock.expect_get_payload_envelope_summary()
        .returning(move |root| Ok(summary_map.get(root).cloned().flatten()));

    let payload_map: HashMap<Hash256, Option<ExecutionPayloadGloas<E>>> = chain
        .iter()
        .map(|entry| {
            (
                entry.block_root,
                entry
                    .envelope
                    .as_ref()
                    .filter(|_| !pruned_payload_slots.contains(&entry.slot.as_u64()))
                    .map(|envelope| envelope.message.payload.clone()),
            )
        })
        .collect();
    mock.expect_get_envelope_payload()
        .returning(move |root| Ok(payload_map.get(root).cloned().flatten()));
}

fn payload_body(payload: &ExecutionPayloadGloas<E>) -> ExecutionPayloadBodyV2 {
    ExecutionPayloadBodyV2 {
        transactions: payload.transactions.clone(),
        withdrawals: Some(payload.withdrawals.clone()),
        block_access_list: Some(payload.block_access_list.clone()),
    }
}

/// Configure `block_has_canonical_payload` based on chain's non-canonical entries.
fn mock_canonical_head(mock: &mut MockEnvelopeStreamerBeaconAdapter<T>, chain: &[SlotEntry]) {
    let non_canonical: Vec<Hash256> = chain
        .iter()
        .filter(|e| e.non_canonical_envelope)
        .map(|e| e.block_root)
        .collect();
    mock.expect_block_has_canonical_payload()
        .returning(move |root| Ok(!non_canonical.contains(root)));
}

fn unwrap_result(
    result: &Arc<PayloadEnvelopeResult<E>>,
) -> &Option<Arc<SignedExecutionPayloadEnvelope<E>>> {
    result
        .as_ref()
        .as_ref()
        .expect("unexpected error in stream result")
}

async fn assert_stream_matches(
    stream: &mut (impl Stream<Item = (Hash256, Arc<PayloadEnvelopeResult<E>>)> + Unpin),
    chain: &[SlotEntry],
    split_slot: Option<Slot>,
) {
    for (i, entry) in chain.iter().enumerate() {
        let (root, result) = stream
            .next()
            .await
            .unwrap_or_else(|| panic!("stream ended early at index {i}"));
        assert_eq!(root, entry.block_root, "root mismatch at index {i}");

        let result = unwrap_result(&result);

        if entry.expect_envelope(split_slot) {
            let envelope = result
                .as_ref()
                .unwrap_or_else(|| panic!("expected Some at index {i} but got None"));
            let expected_envelope = entry.envelope.as_ref().unwrap();
            assert_eq!(
                envelope.as_ref(),
                expected_envelope,
                "envelope mismatch at index {i}"
            );
        } else {
            assert!(
                result.is_none(),
                "expected None at index {i} (missing or non-canonical), got Some"
            );
        }
    }

    assert!(stream.next().await.is_none(), "stream should be exhausted");
}

/// Happy path: all envelopes exist and are canonical.
#[tokio::test]
async fn stream_envelopes_by_range() {
    let chain = build_chain(8, &[], &[], &[]);
    let (mut mock, _runtime) = mock_adapter();
    mock.expect_get_split_slot().return_const(Slot::new(0));
    mock_envelopes(&mut mock, &chain);
    mock_canonical_head(&mut mock, &chain);

    let streamer = PayloadEnvelopeStreamer::new(mock, EnvelopeRequestSource::ByRange);
    let mut stream = streamer.launch_stream(roots(&chain));
    assert_stream_matches(&mut stream, &chain, None).await;
}

/// Mixed chain: skipped slots, missing envelopes, and non-canonical envelopes.
#[tokio::test]
async fn stream_envelopes_by_range_mixed() {
    let chain = build_chain(12, &[3, 8], &[5], &[7, 11]);
    let (mut mock, _runtime) = mock_adapter();
    mock.expect_get_split_slot().return_const(Slot::new(0));
    mock_envelopes(&mut mock, &chain);
    mock_canonical_head(&mut mock, &chain);

    let streamer = PayloadEnvelopeStreamer::new(mock, EnvelopeRequestSource::ByRange);
    let mut stream = streamer.launch_stream(roots(&chain));
    assert_stream_matches(&mut stream, &chain, None).await;
}

/// Non-canonical envelopes before the split slot bypass canonical verification
/// and are returned. Non-canonical envelopes after the split slot are filtered out.
#[tokio::test]
async fn stream_envelopes_by_range_before_split() {
    // Non-canonical envelopes at slots 2 and 4 (before split), slot 8 (after split).
    let chain = build_chain(10, &[], &[], &[2, 4, 8]);
    let split_slot = Slot::new(6);
    let (mut mock, _runtime) = mock_adapter();
    mock.expect_get_split_slot().return_const(split_slot);
    mock_envelopes(&mut mock, &chain);
    mock_canonical_head(&mut mock, &chain);

    let streamer = PayloadEnvelopeStreamer::new(mock, EnvelopeRequestSource::ByRange);
    let mut stream = streamer.launch_stream(roots(&chain));
    assert_stream_matches(&mut stream, &chain, Some(split_slot)).await;
}

#[tokio::test]
async fn stream_envelopes_empty_roots() {
    let (mut mock, _runtime) = mock_adapter();
    mock.expect_get_split_slot().return_const(Slot::new(0));

    let streamer = PayloadEnvelopeStreamer::new(mock, EnvelopeRequestSource::ByRange);
    let mut stream = streamer.launch_stream(vec![]);
    assert!(
        stream.next().await.is_none(),
        "empty roots should produce no results"
    );
}

#[tokio::test]
async fn stream_envelopes_single_root() {
    let chain = build_chain(3, &[], &[], &[]);
    let (mut mock, _runtime) = mock_adapter();
    mock.expect_get_split_slot().return_const(Slot::new(0));
    mock_envelopes(&mut mock, &chain);
    mock_canonical_head(&mut mock, &chain);

    let streamer = PayloadEnvelopeStreamer::new(mock, EnvelopeRequestSource::ByRange);
    let mut stream = streamer.launch_stream(vec![chain[1].block_root]);

    let (root, result) = stream.next().await.expect("should get one result");
    assert_eq!(root, chain[1].block_root);
    let envelope = unwrap_result(&result)
        .as_ref()
        .expect("should have envelope");
    assert_eq!(
        envelope.block_hash(),
        chain[1].envelope.as_ref().unwrap().block_hash(),
    );

    assert!(stream.next().await.is_none(), "stream should be exhausted");
}

/// Payloads pruned at finalization are fetched from the EL and combined with their summaries.
#[tokio::test]
async fn stream_reconstructs_pruned_envelopes() {
    let chain = build_chain(4, &[], &[], &[]);
    let (mut mock, _runtime) = mock_adapter();
    mock.expect_get_split_slot().return_const(Slot::new(5));
    mock_envelopes_with_pruned_payloads(&mut mock, &chain, &[2, 4]);
    mock.expect_block_has_canonical_payload().times(0);

    let payload_bodies: HashMap<ExecutionBlockHash, ExecutionPayloadBodyV2> = chain
        .iter()
        .filter(|entry| [2, 4].contains(&entry.slot.as_u64()))
        .map(|entry| {
            let payload = entry.envelope.as_ref().unwrap().message.payload.clone();
            (payload.block_hash, payload_body(&payload))
        })
        .collect();
    mock.expect_get_payload_bodies_by_hash_v2()
        .times(1)
        .returning(move |block_hashes| {
            Ok(block_hashes
                .into_iter()
                .map(|block_hash| payload_bodies.get(&block_hash).cloned())
                .collect())
        });

    let streamer = PayloadEnvelopeStreamer::new(mock, EnvelopeRequestSource::ByRange);
    let mut stream = streamer.launch_stream(roots(&chain));
    assert_stream_matches(&mut stream, &chain, Some(Slot::new(5))).await;
}

/// Payload-body requests are split at the Engine API's guaranteed 32-hash limit while preserving
/// response order across chunks.
#[tokio::test]
async fn stream_batches_pruned_envelope_requests() {
    let chain = build_chain(65, &[], &[], &[]);
    let pruned_payload_slots = (1..=65).collect::<Vec<_>>();
    let (mut mock, _runtime) = mock_adapter();
    mock.expect_get_split_slot().return_const(Slot::new(66));
    mock_envelopes_with_pruned_payloads(&mut mock, &chain, &pruned_payload_slots);
    mock.expect_block_has_canonical_payload().times(0);

    let payload_bodies: HashMap<ExecutionBlockHash, ExecutionPayloadBodyV2> = chain
        .iter()
        .map(|entry| {
            let payload = entry.envelope.as_ref().unwrap().message.payload.clone();
            (payload.block_hash, payload_body(&payload))
        })
        .collect();
    mock.expect_get_payload_bodies_by_hash_v2()
        .times(3)
        .returning(move |block_hashes| {
            assert!(block_hashes.len() <= MAX_PAYLOAD_BODIES_PER_REQUEST);
            Ok(block_hashes
                .into_iter()
                .map(|block_hash| payload_bodies.get(&block_hash).cloned())
                .collect())
        });

    let streamer = PayloadEnvelopeStreamer::new(mock, EnvelopeRequestSource::ByRange);
    let mut stream = streamer.launch_stream(roots(&chain));
    assert_stream_matches(&mut stream, &chain, Some(Slot::new(66))).await;
}

/// A response with a different number of entries cannot be safely associated with summaries.
#[tokio::test]
async fn stream_rejects_invalid_payload_body_response_length() {
    let chain = build_chain(1, &[], &[], &[]);
    let (mut mock, _runtime) = mock_adapter();
    mock.expect_get_split_slot().return_const(Slot::new(2));
    mock_envelopes_with_pruned_payloads(&mut mock, &chain, &[1]);
    mock.expect_block_has_canonical_payload().times(0);
    mock.expect_get_payload_bodies_by_hash_v2()
        .times(1)
        .returning(|_| Ok(vec![]));

    let streamer = PayloadEnvelopeStreamer::new(mock, EnvelopeRequestSource::ByRange);
    let mut stream = streamer.launch_stream(roots(&chain));
    let (_, result) = stream.next().await.expect("should get one result");
    assert!(matches!(
        result.as_ref(),
        Err(BeaconChainError::EnvelopeStreamerError(
            Error::InvalidPayloadBodiesResponse {
                expected: 1,
                received: 0,
            }
        ))
    ));
    assert!(stream.next().await.is_none());
}

/// An EL that no longer has a requested payload produces an error for that envelope.
#[tokio::test]
async fn stream_handles_payload_missing_from_execution_layer() {
    let chain = build_chain(1, &[], &[], &[]);
    let (mut mock, _runtime) = mock_adapter();
    mock.expect_get_split_slot().return_const(Slot::new(2));
    mock_envelopes_with_pruned_payloads(&mut mock, &chain, &[1]);
    mock.expect_block_has_canonical_payload().times(0);
    mock.expect_get_payload_bodies_by_hash_v2()
        .times(1)
        .returning(|block_hashes| Ok(vec![None; block_hashes.len()]));

    let streamer = PayloadEnvelopeStreamer::new(mock, EnvelopeRequestSource::ByRange);
    let mut stream = streamer.launch_stream(roots(&chain));
    let (_, result) = stream.next().await.expect("should get one result");
    assert!(matches!(
        result.as_ref(),
        Err(BeaconChainError::EnvelopeStreamerError(
            Error::PayloadMissingFromExecutionLayer(_)
        ))
    ));
    assert!(stream.next().await.is_none());
}

/// A payload body that does not match the block hash retained in the summary is rejected.
#[tokio::test]
async fn stream_rejects_payload_body_with_wrong_hash() {
    let chain = build_chain(1, &[], &[], &[]);
    let (mut mock, _runtime) = mock_adapter();
    mock.expect_get_split_slot().return_const(Slot::new(2));
    mock_envelopes_with_pruned_payloads(&mut mock, &chain, &[1]);
    mock.expect_block_has_canonical_payload().times(0);

    let mut wrong_body = payload_body(&chain[0].envelope.as_ref().unwrap().message.payload);
    wrong_body.block_access_list = Some(BlockAccessList::new(vec![1]));
    mock.expect_get_payload_bodies_by_hash_v2()
        .times(1)
        .return_once(move |_| Ok(vec![Some(wrong_body)]));

    let streamer = PayloadEnvelopeStreamer::new(mock, EnvelopeRequestSource::ByRange);
    let mut stream = streamer.launch_stream(roots(&chain));
    let (_, result) = stream.next().await.expect("should get one result");
    assert!(matches!(
        result.as_ref(),
        Err(BeaconChainError::EnvelopeStreamerError(
            Error::ComputedPayloadHashMismatch { .. }
        ))
    ));
    assert!(stream.next().await.is_none());
}

/// A V2 payload body without withdrawals cannot reconstruct a Gloas payload.
#[tokio::test]
async fn stream_rejects_payload_body_without_withdrawals() {
    let chain = build_chain(1, &[], &[], &[]);
    let (mut mock, _runtime) = mock_adapter();
    mock.expect_get_split_slot().return_const(Slot::new(2));
    mock_envelopes_with_pruned_payloads(&mut mock, &chain, &[1]);
    mock.expect_block_has_canonical_payload().times(0);

    let mut body = payload_body(&chain[0].envelope.as_ref().unwrap().message.payload);
    body.withdrawals = None;
    mock.expect_get_payload_bodies_by_hash_v2()
        .times(1)
        .return_once(move |_| Ok(vec![Some(body)]));

    let streamer = PayloadEnvelopeStreamer::new(mock, EnvelopeRequestSource::ByRange);
    let mut stream = streamer.launch_stream(roots(&chain));
    let (_, result) = stream.next().await.expect("should get one result");
    assert!(matches!(
        result.as_ref(),
        Err(BeaconChainError::EnvelopeStreamerError(
            Error::PayloadBodyMissingWithdrawals(_)
        ))
    ));
    assert!(stream.next().await.is_none());
}

/// A V2 payload body without a block access list cannot reconstruct a Gloas payload.
#[tokio::test]
async fn stream_rejects_payload_body_without_block_access_list() {
    let chain = build_chain(1, &[], &[], &[]);
    let (mut mock, _runtime) = mock_adapter();
    mock.expect_get_split_slot().return_const(Slot::new(2));
    mock_envelopes_with_pruned_payloads(&mut mock, &chain, &[1]);
    mock.expect_block_has_canonical_payload().times(0);

    let mut body = payload_body(&chain[0].envelope.as_ref().unwrap().message.payload);
    body.block_access_list = None;
    mock.expect_get_payload_bodies_by_hash_v2()
        .times(1)
        .return_once(move |_| Ok(vec![Some(body)]));

    let streamer = PayloadEnvelopeStreamer::new(mock, EnvelopeRequestSource::ByRange);
    let mut stream = streamer.launch_stream(roots(&chain));
    let (_, result) = stream.next().await.expect("should get one result");
    assert!(matches!(
        result.as_ref(),
        Err(BeaconChainError::EnvelopeStreamerError(
            Error::PayloadBodyMissingBlockAccessList(_)
        ))
    ));
    assert!(stream.next().await.is_none());
}

/// ByRoot requests skip canonical verification, so non-canonical envelopes
/// should still be returned. `block_has_canonical_payload` should never be called.
#[tokio::test]
async fn stream_envelopes_by_root() {
    let chain = build_chain(8, &[], &[], &[3, 5, 7]);
    let (mut mock, _runtime) = mock_adapter();
    mock.expect_get_split_slot().return_const(Slot::new(0));
    mock_envelopes(&mut mock, &chain);
    mock.expect_block_has_canonical_payload().times(0);

    let streamer = PayloadEnvelopeStreamer::new(mock, EnvelopeRequestSource::ByRoot);
    let mut stream = streamer.launch_stream(roots(&chain));

    // Every envelope should come back as Some, even the non-canonical ones.
    for (i, entry) in chain.iter().enumerate() {
        let (root, result) = stream
            .next()
            .await
            .unwrap_or_else(|| panic!("stream ended early at index {i}"));
        assert_eq!(root, entry.block_root, "root mismatch at index {i}");

        let envelope = unwrap_result(&result)
            .as_ref()
            .unwrap_or_else(|| panic!("expected Some at index {i} for ByRoot request"));
        let expected_envelope = entry.envelope.as_ref().unwrap();
        assert_eq!(
            envelope.block_hash(),
            expected_envelope.block_hash(),
            "block_hash mismatch at index {i}"
        );
    }

    assert!(stream.next().await.is_none(), "stream should be exhausted");
}

/// When `block_has_canonical_payload` returns an error, the streamer should
/// propagate that error for those roots.
#[tokio::test]
async fn stream_envelopes_error() {
    let chain = build_chain(4, &[], &[], &[]);
    let (mut mock, _runtime) = mock_adapter();
    mock.expect_get_split_slot().return_const(Slot::new(0));
    mock_envelopes(&mut mock, &chain);
    mock.expect_block_has_canonical_payload().returning(|_| {
        Err(BeaconChainError::ForkChoiceError(
            ForkChoiceError::DoesNotDescendFromFinalizedCheckpoint,
        ))
    });

    let streamer = PayloadEnvelopeStreamer::new(mock, EnvelopeRequestSource::ByRange);
    let mut stream = streamer.launch_stream(roots(&chain));

    for (i, entry) in chain.iter().enumerate() {
        let (root, result) = stream
            .next()
            .await
            .unwrap_or_else(|| panic!("stream ended early at index {i}"));
        assert_eq!(root, entry.block_root, "root mismatch at index {i}");
        assert!(
            result.as_ref().is_err(),
            "expected error at index {i}, got {:?}",
            result
        );
    }

    assert!(stream.next().await.is_none(), "stream should be exhausted");
}

/// Requesting unknown roots (not in the store) via ByRange should return Ok(None).
#[tokio::test]
async fn stream_envelopes_by_range_unknown_roots() {
    let (mut mock, _runtime) = mock_adapter();
    mock.expect_get_split_slot().return_const(Slot::new(0));
    mock.expect_get_payload_envelope_summary()
        .returning(|_| Ok(None));

    let unknown_roots: Vec<Hash256> = (1..=4)
        .map(|i| Hash256::from_low_u64_be(i * 1000))
        .collect();

    let streamer = PayloadEnvelopeStreamer::new(mock, EnvelopeRequestSource::ByRange);
    let mut stream = streamer.launch_stream(unknown_roots.clone());

    for (i, expected_root) in unknown_roots.iter().enumerate() {
        let (root, result) = stream
            .next()
            .await
            .unwrap_or_else(|| panic!("stream ended early at index {i}"));
        assert_eq!(root, *expected_root, "root mismatch at index {i}");
        let envelope = unwrap_result(&result);
        assert!(
            envelope.is_none(),
            "expected None for unknown root at index {i}"
        );
    }

    assert!(stream.next().await.is_none(), "stream should be exhausted");
}

/// Requesting roots via ByRoot where some envelopes are missing should
/// return Ok(None) for those roots.
#[tokio::test]
async fn stream_envelopes_by_root_missing_envelopes() {
    let chain = build_chain(6, &[], &[2, 4], &[]);
    let (mut mock, _runtime) = mock_adapter();
    mock.expect_get_split_slot().return_const(Slot::new(0));
    mock_envelopes(&mut mock, &chain);
    mock.expect_block_has_canonical_payload().times(0);

    let streamer = PayloadEnvelopeStreamer::new(mock, EnvelopeRequestSource::ByRoot);
    let mut stream = streamer.launch_stream(roots(&chain));

    for (i, entry) in chain.iter().enumerate() {
        let (root, result) = stream
            .next()
            .await
            .unwrap_or_else(|| panic!("stream ended early at index {i}"));
        assert_eq!(root, entry.block_root, "root mismatch at index {i}");

        let envelope_opt = unwrap_result(&result);
        if let Some(entry_envelope) = &entry.envelope {
            let envelope = envelope_opt
                .as_ref()
                .unwrap_or_else(|| panic!("expected Some at index {i}"));
            assert_eq!(
                envelope.block_hash(),
                entry_envelope.block_hash(),
                "block_hash mismatch at index {i}"
            );
        } else {
            assert!(
                envelope_opt.is_none(),
                "expected None for missing envelope at index {i}"
            );
        }
    }

    assert!(stream.next().await.is_none(), "stream should be exhausted");
}
