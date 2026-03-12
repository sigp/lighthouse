use std::sync::Arc;

use bls::Hash256;
use execution_layer::ExecutionLayer;
use futures::Stream;
use itertools::Itertools;
use task_executor::TaskExecutor;
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::{debug, warn};
use types::{EthSpec, SignedExecutionPayloadEnvelope, Slot};

use crate::{BeaconChainError, BeaconChainTypes, BeaconStore};

type PayloadEnvelopeResult<E> =
    Result<Option<Arc<SignedExecutionPayloadEnvelope<E>>>, BeaconChainError>;

#[derive(Debug)]
pub enum Error {
    BlockNotFound,
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

    async fn load_envelopes(
        self: &Arc<Self>,
        beacon_block_roots: &[Hash256],
    ) -> Result<Vec<(Hash256, PayloadEnvelopeResult<T::EthSpec>)>, BeaconChainError> {
        let streamer = self.clone();
        let roots = beacon_block_roots.to_vec();
        let split_slot = streamer.store.get_split_info().slot;
        // Loading from the DB is slow -> spawn a blocking task
        self.task_executor
            .spawn_blocking_and_await(
                move || {
                    let mut results = Vec::new();
                    let mut latest_slot = Slot::new(0);
                    for (root, next_root) in roots.into_iter().tuple_windows() {
                        let opt_envelope = if let Some(cached_envelope) =
                            streamer.check_payload_envelope_cache(&root)
                        {
                            Some(cached_envelope)
                        } else {
                            // TODO(gloas) we'll want to use the execution layer directly to call
                            //  the engine api method eth_getBlockByHash()
                            match streamer.store.get_payload_envelope(&root) {
                                Ok(opt_envelope) => opt_envelope.map(Arc::new),
                                Err(e) => {
                                    results.push((root, Err(BeaconChainError::DBError(e))));
                                    continue;
                                }
                            }
                        };

                        // Ensure that the envelopes we're serving match our view of the canonical chain.
                        // When loading envelopes before the split slot, there is no need to check the
                        // envelopes blocks. Non-canonical payload envelopes will have already been pruned.
                        if split_slot > latest_slot {
                            results.push((root, Ok(opt_envelope)));
                            continue;
                        }

                        // When loading envelopes on or after the split slot, we must check the envelopes block.
                        // There can be payloads that have been imported into the hot db but don't match our current view
                        // of the canonical chain.
                        let Ok(Some(next_beacon_block)) = streamer.store.get_full_block(&next_root)
                        else {
                            results.push((
                                root,
                                Err(BeaconChainError::EnvelopeStreamerError(
                                    Error::BlockNotFound,
                                )),
                            ));
                            continue;
                        };

                        if let Some(envelope) = opt_envelope {
                            // TODO(gloas) use michaels execution block hash from bid fn
                            if envelope.block_hash()
                                == next_beacon_block
                                    .as_gloas()
                                    .unwrap()
                                    .message
                                    .body
                                    .signed_execution_payload_bid
                                    .message
                                    .block_hash
                            {
                                latest_slot = envelope.slot();
                                results.push((root, Ok(Some(envelope))));
                            } else {
                                results.push((root, Ok(None)));
                            }
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
        beacon_block_roots: Vec<Hash256>,
        sender: UnboundedSender<(Hash256, Arc<PayloadEnvelopeResult<T::EthSpec>>)>,
    ) {
        let results = match self.load_envelopes(&beacon_block_roots).await {
            Ok(results) => results,
            Err(e) => {
                warn!(error = ?e, "Failed to load payload envelopes");
                send_errors(&beacon_block_roots, sender, e).await;
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
        beacon_block_roots: Vec<Hash256>,
    ) -> impl Stream<Item = (Hash256, Arc<PayloadEnvelopeResult<T::EthSpec>>)> {
        let (envelope_tx, envelope_rx) = mpsc::unbounded_channel();
        debug!(
            envelopes = beacon_block_roots.len(),
            "Launching a PayloadEnvelopeStreamer"
        );
        let executor = self.task_executor.clone();
        executor.spawn(
            self.stream_payload_envelopes(beacon_block_roots, envelope_tx),
            "get_payload_envelopes_sender",
        );
        UnboundedReceiverStream::new(envelope_rx)
    }
}

async fn send_errors<E: EthSpec>(
    beacon_block_roots_and_slots: &[Hash256],
    sender: UnboundedSender<(Hash256, Arc<PayloadEnvelopeResult<E>>)>,
    beacon_chain_error: BeaconChainError,
) {
    let result = Arc::new(Err(beacon_chain_error));
    for beacon_block_root in beacon_block_roots_and_slots {
        if sender.send((*beacon_block_root, result.clone())).is_err() {
            break;
        }
    }
}
