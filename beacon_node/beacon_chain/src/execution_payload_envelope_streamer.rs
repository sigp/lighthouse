use std::sync::Arc;

use bls::Hash256;
use execution_layer::ExecutionLayer;
use futures::Stream;
use task_executor::TaskExecutor;
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::debug;
use types::{EthSpec, SignedExecutionPayloadEnvelope};

use crate::{BeaconChainError, BeaconChainTypes, BeaconStore, beacon_block_streamer::CheckCaches};

type PayloadEnvelopeResult<E> =
    Result<Option<Arc<SignedExecutionPayloadEnvelope<E>>>, BeaconChainError>;

pub struct PayloadEnvelopeStreamer<T: BeaconChainTypes> {
    // TODO(gloas) remove _ when we use the execution layer
    // to load payload envelopes
    _execution_layer: ExecutionLayer<T::EthSpec>,
    store: BeaconStore<T>,
    task_executor: TaskExecutor,
    _check_caches: CheckCaches,
}

// TODO(gloas) eventually we'll need to expand this to support loading blinded payload envelopes from the db
// and fetching the execution payload from the EL. See BlockStreamer impl as an example
impl<T: BeaconChainTypes> PayloadEnvelopeStreamer<T> {
    pub fn new(
        execution_layer_opt: Option<ExecutionLayer<T::EthSpec>>,
        store: BeaconStore<T>,
        task_executor: TaskExecutor,
        check_caches: CheckCaches,
    ) -> Result<Arc<Self>, BeaconChainError> {
        let execution_layer = execution_layer_opt
            .as_ref()
            .ok_or(BeaconChainError::ExecutionLayerMissing)?
            .clone();

        Ok(Arc::new(Self {
            _execution_layer: execution_layer,
            store,
            task_executor,
            _check_caches: check_caches,
        }))
    }

    // TODO(gloas) simply a stub impl for now. Should check some exec payload envelope cache
    // and return the envelope if it exists in the cache
    fn check_payload_envelope_cache(
        &self,
        _beacon_block_root: Hash256,
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
        // Loading from the DB is slow -> spawn a blocking task
        self.task_executor
            .spawn_blocking_and_await(
                move || {
                    let mut results = Vec::new();
                    for root in roots {
                        if let Some(cached) = streamer.check_payload_envelope_cache(root) {
                            results.push((root, Ok(Some(cached))));
                            continue;
                        }
                        // TODO(gloas) we'll want to use the execution layer directly to call
                        //  the engine api method eth_getBlockByHash()
                        match streamer.store.get_payload_envelope(&root) {
                            Ok(opt_envelope) => {
                                results.push((root, Ok(opt_envelope.map(Arc::new))));
                            }
                            Err(e) => {
                                results.push((root, Err(BeaconChainError::DBError(e))));
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
                send_errors(beacon_block_roots, sender, e).await;
                return;
            }
        };

        for (root, result) in results {
            if sender.send((root, Arc::new(result))).is_err() {
                break;
            }
        }
    }

    pub async fn stream(
        self: Arc<Self>,
        beacon_block_roots: Vec<Hash256>,
        sender: UnboundedSender<(Hash256, Arc<PayloadEnvelopeResult<T::EthSpec>>)>,
    ) {
        self.stream_payload_envelopes(beacon_block_roots, sender)
            .await;
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
            self.stream(beacon_block_roots, envelope_tx),
            "get_payload_envelopes_sender",
        );
        UnboundedReceiverStream::new(envelope_rx)
    }
}

async fn send_errors<E: EthSpec>(
    beacon_block_roots: Vec<Hash256>,
    sender: UnboundedSender<(Hash256, Arc<PayloadEnvelopeResult<E>>)>,
    beacon_chain_error: BeaconChainError,
) {
    let result = Arc::new(Err(beacon_chain_error));
    for beacon_block_root in beacon_block_roots {
        if sender.send((beacon_block_root, result.clone())).is_err() {
            break;
        }
    }
}
