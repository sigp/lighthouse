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
    execution_layer: ExecutionLayer<T::EthSpec>,
    store: BeaconStore<T>,
    task_executor: TaskExecutor,
    _check_caches: CheckCaches,
}

// TODO(gloas) eventually we'll need to expand this to support loading blinded payload envelopes from the dsb
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
            execution_layer,
            store,
            task_executor,
            _check_caches: check_caches,
        }))
    }

    // TODO(gloas) simply a strub impl for now. Should check some exec payload envelope cache
    // and return the envelope if it exists in the cache
    fn check_payload_envelope_cache(
        &self,
        _beacon_block_root: Hash256,
    ) -> Option<Arc<SignedExecutionPayloadEnvelope<T::EthSpec>>> {
        // if self.check_caches == CheckCaches::Yes
        None
    }

    // used when the execution engine doesn't support the payload bodies methods
    async fn stream_payload_envelopes_fallback(
        self: Arc<Self>,
        beacon_block_roots: Vec<Hash256>,
        sender: UnboundedSender<(Hash256, Arc<PayloadEnvelopeResult<T::EthSpec>>)>,
    ) {
        debug!("Using slower fallback method of eth_getBlockByHash()");
        for beacon_block_root in beacon_block_roots {
            let cached_envelope = self.check_payload_envelope_cache(beacon_block_root);

            let envelope_result = if cached_envelope.is_some() {
                Ok(cached_envelope)
            } else {
                // TODO(gloas) we'll want to use the execution layer directly to call
                //  the engine api method eth_getBlockByHash()
                self.store
                    .get_payload_envelope(&beacon_block_root)
                    .map(|opt_envelope| opt_envelope.map(Arc::new))
                    .map_err(BeaconChainError::DBError)
            };

            if sender
                .send((beacon_block_root, Arc::new(envelope_result)))
                .is_err()
            {
                break;
            }
        }
    }

    pub async fn stream(
        self: Arc<Self>,
        beacon_block_roots: Vec<Hash256>,
        sender: UnboundedSender<(Hash256, Arc<PayloadEnvelopeResult<T::EthSpec>>)>,
    ) {
        match self
            .execution_layer
            .get_engine_capabilities(None)
            .await
            .map_err(Box::new)
            .map_err(BeaconChainError::EngineGetCapabilititesFailed)
        {
            Ok(_engine_capabilities) => {
                // TODO(gloas) should check engine capabilities for get_payload_bodies_by_range_v1
                self.stream_payload_envelopes_fallback(beacon_block_roots, sender)
                    .await;
            }
            Err(e) => {
                send_errors(beacon_block_roots, sender, e).await;
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
