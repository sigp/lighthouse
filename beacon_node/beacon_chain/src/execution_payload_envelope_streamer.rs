use std::sync::Arc;

use bls::Hash256;
use execution_layer::ExecutionLayer;
use futures::Stream;
use task_executor::TaskExecutor;
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::{debug, warn};
use types::{EthSpec, SignedExecutionPayloadEnvelope};

use crate::{BeaconChainError, BeaconChainTypes, BeaconStore};

type PayloadEnvelopeResult<E> =
    Result<Option<Arc<SignedExecutionPayloadEnvelope<E>>>, BeaconChainError>;

#[derive(Debug)]
pub enum Error {
    ChildBlockNotFound,
}

pub struct PayloadEnvelopeStreamer<T: BeaconChainTypes> {
    // TODO(gloas) remove expect when execution layer field
    // is no longer dead.
    #[expect(dead_code)]
    execution_layer: ExecutionLayer<T::EthSpec>,
    store: BeaconStore<T>,
    task_executor: TaskExecutor,
}

// TODO(gloas) eventually we'll need to expand this to support loading blinded payload envelopes from the db
// and fetching the execution payload from the EL. See BlockStreamer impl as an example
impl<T: BeaconChainTypes> PayloadEnvelopeStreamer<T> {
    pub fn new(
        execution_layer_opt: Option<ExecutionLayer<T::EthSpec>>,
        store: BeaconStore<T>,
        task_executor: TaskExecutor,
    ) -> Result<Arc<Self>, BeaconChainError> {
        let execution_layer = execution_layer_opt
            .as_ref()
            .ok_or(BeaconChainError::ExecutionLayerMissing)?
            .clone();

        Ok(Arc::new(Self {
            execution_layer,
            store,
            task_executor,
        }))
    }

    // TODO(gloas) simply a stub impl for now. Should check some exec payload envelope cache
    // and return the envelope if it exists in the cache
    fn check_payload_envelope_cache(
        &self,
        _beacon_block_root: &Hash256,
    ) -> Option<Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>> {
        // if self.check_caches == CheckCaches::Yes
        None
    }

    fn load_envelope(
        self: &Arc<Self>,
        beacon_block_root: &Hash256,
    ) -> Result<Option<Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>>, BeaconChainError> {
        if let Some(cached_envelope) = self.check_payload_envelope_cache(beacon_block_root) {
            Ok(Some(cached_envelope))
        } else {
            // TODO(gloas) we'll want to use the execution layer directly to call
            //  the engine api method eth_getBlockByHash()
            match self.store.get_payload_envelope(beacon_block_root) {
                Ok(opt_envelope) => Ok(opt_envelope.map(Arc::new)),
                Err(e) => Err(BeaconChainError::DBError(e)),
            }
        }
    }

    async fn load_envelopes(
        self: &Arc<Self>,
        block_roots_with_children: &[(Hash256, Option<Hash256>)],
    ) -> Result<Vec<(Hash256, PayloadEnvelopeResult<T::EthSpec>)>, BeaconChainError> {
        let streamer = self.clone();
        let roots_with_children = block_roots_with_children.to_vec();
        let split_slot = streamer.store.get_split_info().slot;
        // Loading from the DB is slow -> spawn a blocking task
        self.task_executor
            .spawn_blocking_and_await(
                move || {
                    let mut results = Vec::new();
                    for (root, child_root_opt) in roots_with_children.iter() {
                        let opt_envelope = match streamer.load_envelope(root) {
                            Ok(opt_envelope) => opt_envelope,
                            Err(e) => {
                                results.push((*root, Err(e)));
                                continue;
                            }
                        };

                        let Some(child_root) = child_root_opt else {
                            // No child root provided, skip verification
                            // TODO(gloas) envelopes by root skips verificiation completely
                            // envelopes by range skips verification for the last envelope
                            // it returns.
                            results.push((*root, Ok(opt_envelope)));
                            continue;
                        };

                        // When loading envelopes on or after the split slot, we must cross reference the bid from the child beacon block.
                        // There can be payloads that have been imported into the hot db but don't match our current view
                        // of the canonical chain.

                        if let Some(envelope) = opt_envelope {
                            // Ensure that the envelopes we're serving match our view of the canonical chain.
                            // When loading envelopes before the split slot, there is no need to cross reference the
                            // child block. Non-canonical payload envelopes will have already been pruned.
                            if split_slot > envelope.slot() {
                                results.push((*root, Ok(Some(envelope))));
                                continue;
                            }

                            let Ok(Some(child_beacon_block)) =
                                streamer.store.get_full_block(child_root)
                            else {
                                results.push((
                                    *root,
                                    Err(BeaconChainError::EnvelopeStreamerError(
                                        Error::ChildBlockNotFound,
                                    )),
                                ));
                                continue;
                            };

                            // If the child beacon block `parent_block_hash` equals the current slots envelope `block_hash`
                            // this envelope is canonical according to our view of the chain.
                            if child_beacon_block
                                .payload_bid_parent_block_hash()
                                .is_ok_and(|parent_hash| parent_hash == envelope.block_hash())
                            {
                                results.push((*root, Ok(Some(envelope))));
                            } else {
                                results.push((*root, Ok(None)));
                            }
                        } else {
                            results.push((*root, Ok(None)));
                        }
                    }

                    results
                },
                "load_execution_payload_envelopes",
            )
            .await
            .map_err(BeaconChainError::from)
    }

    async fn stream_payload_envelopes(
        self: Arc<Self>,
        beacon_block_roots_and_children: Vec<(Hash256, Option<Hash256>)>,
        sender: UnboundedSender<(Hash256, Arc<PayloadEnvelopeResult<T::EthSpec>>)>,
    ) {
        let results = match self.load_envelopes(&beacon_block_roots_and_children).await {
            Ok(results) => results,
            Err(e) => {
                warn!(error = ?e, "Failed to load payload envelopes");
                send_errors(&beacon_block_roots_and_children, sender, e).await;
                return;
            }
        };

        for (root, result) in results {
            if sender.send((root, Arc::new(result))).is_err() {
                break;
            }
        }
    }

    pub fn launch_stream(
        self: Arc<Self>,
        block_roots_with_children: Vec<(Hash256, Option<Hash256>)>,
    ) -> impl Stream<Item = (Hash256, Arc<PayloadEnvelopeResult<T::EthSpec>>)> {
        let (envelope_tx, envelope_rx) = mpsc::unbounded_channel();
        debug!(
            envelopes = block_roots_with_children.len(),
            "Launching a PayloadEnvelopeStreamer"
        );
        let executor = self.task_executor.clone();
        executor.spawn(
            self.stream_payload_envelopes(block_roots_with_children, envelope_tx),
            "get_payload_envelopes_sender",
        );
        UnboundedReceiverStream::new(envelope_rx)
    }
}

async fn send_errors<E: EthSpec>(
    block_roots_with_children: &[(Hash256, Option<Hash256>)],
    sender: UnboundedSender<(Hash256, Arc<PayloadEnvelopeResult<E>>)>,
    beacon_chain_error: BeaconChainError,
) {
    let result = Arc::new(Err(beacon_chain_error));
    for (beacon_block_root, _) in block_roots_with_children {
        if sender.send((*beacon_block_root, result.clone())).is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::EphemeralHarnessType;
    use bls::{FixedBytesExtended, Signature};
    use futures::StreamExt;
    use ssz_types::VariableList;
    use std::marker::PhantomData;
    use store::StoreConfig;
    use types::{
        BeaconBlock, BeaconBlockBodyGloas, BeaconBlockGloas, Eth1Data, ExecutionBlockHash,
        ExecutionPayloadEnvelope, ExecutionPayloadGloas, ForkName, Graffiti, MinimalEthSpec,
        SignedBeaconBlock, SignedExecutionPayloadBid, Slot,
    };

    type E = MinimalEthSpec;
    type T = EphemeralHarnessType<E>;

    struct TestSetup {
        store: BeaconStore<T>,
        el: ExecutionLayer<E>,
        executor: TaskExecutor,
        _runtime: task_executor::test_utils::TestRuntime,
    }

    impl TestSetup {
        fn store(&self) -> &BeaconStore<T> {
            &self.store
        }

        /// Consume setup and return a `(stream, _runtime)` pair.
        /// The runtime must be kept alive for the stream to produce results.
        fn launch_stream(
            self,
            roots_with_children: Vec<(Hash256, Option<Hash256>)>,
        ) -> (
            impl Stream<Item = (Hash256, Arc<PayloadEnvelopeResult<E>>)>,
            task_executor::test_utils::TestRuntime,
        ) {
            let streamer =
                PayloadEnvelopeStreamer::<T>::new(Some(self.el), self.store, self.executor)
                    .unwrap();
            (streamer.launch_stream(roots_with_children), self._runtime)
        }
    }

    fn setup() -> TestSetup {
        let spec = Arc::new(ForkName::Gloas.make_genesis_spec(E::default_spec()));
        let store = Arc::new(
            store::HotColdDB::open_ephemeral(StoreConfig::default(), spec.clone()).unwrap(),
        );

        let runtime = task_executor::test_utils::TestRuntime::default();
        let executor = runtime.task_executor.clone();

        let mock_el =
            execution_layer::test_utils::MockExecutionLayer::default_params(executor.clone());

        TestSetup {
            store,
            el: mock_el.el,
            executor,
            _runtime: runtime,
        }
    }

    struct SlotEntry {
        block_root: Hash256,
        block: SignedBeaconBlock<E>,
        /// `None` when this slot had no envelope (missing payload).
        envelope: Option<SignedExecutionPayloadEnvelope<E>>,
        /// Whether the stored envelope is non-canonical (block_hash doesn't match
        /// what the child block's bid expects).
        non_canonical_envelope: bool,
    }

    impl SlotEntry {
        /// Wether the streamer should return an envelope for this entry.
        fn expect_envelope(&self, is_last: bool, split_slot: Option<Slot>) -> bool {
            if self.envelope.is_none() {
                return false;
            }
            if !self.non_canonical_envelope {
                return true;
            }
            // TODO(gloas) no child block verification happens for envelopes in the last slot
            // of the stream.
            if is_last {
                return true;
            }

            // no child block verification happens for envelopes before the split slot
            split_slot.is_some_and(|s| self.block.slot() < s)
        }
    }

    fn roots_with_children(chain: &[SlotEntry]) -> Vec<(Hash256, Option<Hash256>)> {
        let mut result: Vec<(Hash256, Option<Hash256>)> = chain
            .windows(2)
            .map(|w| (w[0].block_root, Some(w[1].block_root)))
            .collect();
        if let Some(last) = chain.last() {
            result.push((last.block_root, None));
        }
        result
    }

    fn assert_non_canonical_envelopes_in_db(store: &BeaconStore<T>, chain: &[SlotEntry]) {
        for entry in chain.iter().filter(|e| e.non_canonical_envelope) {
            assert!(
                store
                    .get_payload_envelope(&entry.block_root)
                    .unwrap()
                    .is_some(),
                "non-canonical envelope for root {:?} should exist in DB",
                entry.block_root
            );
        }
    }

    /// Build a chain of gloas blocks and envelopes across `num_slots` slots. By
    /// default a slot will contain a block and canonical payload envelope unless
    /// the slot number is provided in one of the following arguments:
    ///
    /// - `skipped_slots`: slots with no block and no envelope (skipped entirely).
    /// - `missing_envelope_slots`: slots with a block but no envelope.
    /// - `non_canonical_envelope_slots`: slots where an envelope exists in the DB but isn't
    ///   part of the canonical chain.
    fn build_chain(
        num_slots: u64,
        skipped_slots: &[u64],
        missing_envelope_slots: &[u64],
        non_canonical_envelope_slots: &[u64],
    ) -> Vec<SlotEntry> {
        let mut chain = Vec::new();
        // Tracks the block_hash of the most recent canonical envelope.
        let mut latest_canonical_block_hash =
            ExecutionBlockHash::from_root(Hash256::repeat_byte(0x00));
        let mut prev_block_root = Hash256::zero();

        for i in 1..=num_slots {
            if skipped_slots.contains(&i) {
                continue;
            }

            let slot = Slot::new(i);
            let has_envelope = !missing_envelope_slots.contains(&i);
            let is_non_canonical_envelope = non_canonical_envelope_slots.contains(&i);

            // The canonical block_hash for this slot.
            let canonical_block_hash = ExecutionBlockHash::from_root(Hash256::from_low_u64_be(i));

            // The bid always points to the latest *canonical* payload.
            let mut bid = types::ExecutionPayloadBid::default();
            bid.parent_block_hash = latest_canonical_block_hash;
            bid.block_hash = canonical_block_hash;
            bid.slot = slot;
            let signed_bid = SignedExecutionPayloadBid {
                message: bid,
                signature: Signature::empty(),
            };

            let block = BeaconBlock::Gloas(BeaconBlockGloas {
                slot,
                proposer_index: 0,
                parent_root: prev_block_root,
                state_root: Hash256::zero(),
                body: BeaconBlockBodyGloas {
                    randao_reveal: Signature::empty(),
                    eth1_data: Eth1Data {
                        deposit_root: Hash256::zero(),
                        block_hash: Hash256::zero(),
                        deposit_count: 0,
                    },
                    graffiti: Graffiti::default(),
                    proposer_slashings: VariableList::empty(),
                    attester_slashings: VariableList::empty(),
                    attestations: VariableList::empty(),
                    deposits: VariableList::empty(),
                    voluntary_exits: VariableList::empty(),
                    sync_aggregate: types::SyncAggregate::empty(),
                    bls_to_execution_changes: VariableList::empty(),
                    signed_execution_payload_bid: signed_bid,
                    payload_attestations: VariableList::empty(),
                    _phantom: PhantomData,
                },
            });
            let signed_block = SignedBeaconBlock::from_block(block, Signature::empty());
            let block_root = signed_block.canonical_root();

            let envelope = if has_envelope {
                // Non-canonical envelopes get a junk block_hash that won't match
                // the child block's bid.parent_block_hash.
                let stored_block_hash = if is_non_canonical_envelope {
                    ExecutionBlockHash::from_root(Hash256::repeat_byte(0xFF))
                } else {
                    canonical_block_hash
                };

                let mut payload = ExecutionPayloadGloas::default();
                payload.block_hash = stored_block_hash;

                let env = SignedExecutionPayloadEnvelope {
                    message: ExecutionPayloadEnvelope {
                        payload,
                        execution_requests: Default::default(),
                        builder_index: 0,
                        beacon_block_root: block_root,
                        slot,
                        state_root: Hash256::zero(),
                    },
                    signature: Signature::empty(),
                };

                if !is_non_canonical_envelope {
                    latest_canonical_block_hash = canonical_block_hash;
                }

                Some(env)
            } else {
                None
            };

            prev_block_root = block_root;

            chain.push(SlotEntry {
                block_root,
                block: signed_block,
                envelope,
                non_canonical_envelope: is_non_canonical_envelope,
            });
        }

        chain
    }

    /// Store blocks and envelopes from a chain into the store.
    fn store_chain(store: &BeaconStore<T>, chain: &[SlotEntry]) {
        for item in chain {
            store
                .put_block(&item.block_root, item.block.clone())
                .unwrap();
            if let Some(ref envelope) = item.envelope {
                store
                    .put_payload_envelope(&item.block_root, envelope.clone())
                    .unwrap();
            }
        }
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
            let is_last = i == chain.len() - 1;

            if entry.expect_envelope(is_last, split_slot) {
                let envelope = result
                    .as_ref()
                    .unwrap_or_else(|| panic!("expected Some at index {i} but got None"));
                let expected_envelope = entry.envelope.as_ref().unwrap();
                assert_eq!(
                    envelope.block_hash(),
                    expected_envelope.block_hash(),
                    "block_hash mismatch at index {i}"
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

    /// Test streaming with no missing slots and no missing payloads i.e. the happy path.
    #[tokio::test]
    async fn stream_envelopes() {
        let test = setup();
        let chain = build_chain(8, &[], &[], &[]);
        store_chain(test.store(), &chain);

        let (mut stream, _runtime) = test.launch_stream(roots_with_children(&chain));

        assert_stream_matches(&mut stream, &chain, None).await;
    }

    /// Test streaming when the chain is a mixture of missed slots, no payloads and non-canonical payloads
    #[tokio::test]
    async fn stream_envelopes_mixed() {
        let test = setup();
        let chain = build_chain(12, &[3, 8], &[5], &[7, 11]);
        store_chain(test.store(), &chain);
        assert_non_canonical_envelopes_in_db(test.store(), &chain);

        let (mut stream, _runtime) = test.launch_stream(roots_with_children(&chain));

        assert_stream_matches(&mut stream, &chain, None).await;
    }

    /// Envelopes before the split slot bypass child block verification.
    /// This test adds some non-canonical envelopes before the split slot, which are then
    /// returned by the streamer. In reality, these non-canonical envelopes will have
    /// been pruned. This test is strictly to show that envelopes before the split slot
    /// are returned without any additional verification.
    #[tokio::test]
    async fn stream_envelopes_before_split() {
        let test = setup();
        // Non-canonical envelopes at slots 2 and 4 (before split), slot 8 (after split).
        let chain = build_chain(10, &[], &[], &[2, 4, 8]);
        store_chain(test.store(), &chain);
        assert_non_canonical_envelopes_in_db(test.store(), &chain);

        // Set split at slot 6 — slots 1-5 are "cold", slots 6+ are "hot".
        let split_slot = Slot::new(6);
        test.store()
            .set_split(split_slot, Hash256::zero(), Hash256::zero());

        let (mut stream, _runtime) = test.launch_stream(roots_with_children(&chain));

        assert_stream_matches(&mut stream, &chain, Some(split_slot)).await;
    }

    #[tokio::test]
    async fn stream_envelopes_empty_roots() {
        let test = setup();
        let (mut stream, _runtime) = test.launch_stream(vec![]);
        assert!(
            stream.next().await.is_none(),
            "empty roots should produce no results"
        );
    }

    /// TODO(gloas) at the moment single root hits the "last root" path which skips child verification.
    #[tokio::test]
    async fn stream_envelopes_single_root() {
        let test = setup();
        let chain = build_chain(3, &[], &[], &[]);
        store_chain(test.store(), &chain);

        let (mut stream, _runtime) = test.launch_stream(vec![(chain[1].block_root, None)]);

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

    /// Test that a missing child block produces a ChildBlockNotFound error.
    #[tokio::test]
    async fn stream_envelopes_missing_child_block() {
        let test = setup();
        let chain = build_chain(4, &[], &[], &[]);

        // Store only the first two blocks+envelopes, skip storing block 3.
        // Then request roots [1, 2, 3] — root 2 has an envelope but its child
        // (root 3) has no block in the DB.
        for item in &chain[..2] {
            test.store()
                .put_block(&item.block_root, item.block.clone())
                .unwrap();
            test.store()
                .put_payload_envelope(&item.block_root, item.envelope.as_ref().unwrap().clone())
                .unwrap();
        }
        // Store envelope for root 3 but NOT the block.
        test.store()
            .put_payload_envelope(
                &chain[2].block_root,
                chain[2].envelope.as_ref().unwrap().clone(),
            )
            .unwrap();

        let roots = vec![
            (chain[0].block_root, Some(chain[1].block_root)),
            (chain[1].block_root, Some(chain[2].block_root)),
            (chain[2].block_root, None),
        ];
        let (mut stream, _runtime) = test.launch_stream(roots);

        let (root, result) = stream.next().await.unwrap();
        assert_eq!(root, chain[0].block_root);
        assert!(unwrap_result(&result).is_some());

        // An envelope exists but its child block doesn't
        let (root, result) = stream.next().await.unwrap();
        assert_eq!(root, chain[1].block_root);
        assert!(
            matches!(
                result.as_ref(),
                Err(BeaconChainError::EnvelopeStreamerError(
                    Error::ChildBlockNotFound
                ))
            ),
            "expected ChildBlockNotFound error, got {:?}",
            result
        );

        let (root, result) = stream.next().await.unwrap();
        assert_eq!(root, chain[2].block_root);
        assert!(unwrap_result(&result).is_some());

        assert!(stream.next().await.is_none(), "stream should be exhausted");
    }
}
