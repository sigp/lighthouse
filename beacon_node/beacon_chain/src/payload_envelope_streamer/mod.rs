mod beacon_chain_adapter;
#[cfg(test)]
mod tests;

use std::sync::Arc;

#[cfg_attr(test, double)]
use crate::payload_envelope_streamer::beacon_chain_adapter::EnvelopeStreamerBeaconAdapter;
use futures::Stream;
#[cfg(test)]
use mockall_double::double;
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::{debug, error, warn};
use types::{EthSpec, Hash256, SignedExecutionPayloadEnvelope};

#[cfg(not(test))]
use crate::BeaconChain;
use crate::{BeaconChainError, BeaconChainTypes};

type PayloadEnvelopeResult<E> =
    Result<Option<Arc<SignedExecutionPayloadEnvelope<E>>>, BeaconChainError>;

#[derive(Debug)]
pub enum Error {
    BlockMissingFromForkChoice,
}

#[derive(Debug, PartialEq)]
pub enum EnvelopeRequestSource {
    ByRoot,
    ByRange,
}

pub struct PayloadEnvelopeStreamer<T: BeaconChainTypes> {
    adapter: EnvelopeStreamerBeaconAdapter<T>,
    request_source: EnvelopeRequestSource,
}

// TODO(gloas) eventually we'll need to expand this to support loading blinded payload envelopes from the db
// and fetching the execution payload from the EL. See BlockStreamer impl as an example
impl<T: BeaconChainTypes> PayloadEnvelopeStreamer<T> {
    pub(crate) fn new(
        adapter: EnvelopeStreamerBeaconAdapter<T>,
        request_source: EnvelopeRequestSource,
    ) -> Arc<Self> {
        Arc::new(Self {
            adapter,
            request_source,
        })
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
            //  the engine api method eth_getPayloadBodiesByRange()
            match self.adapter.get_payload_envelope(beacon_block_root) {
                Ok(opt_envelope) => Ok(opt_envelope.map(Arc::new)),
                Err(e) => Err(BeaconChainError::DBError(e)),
            }
        }
    }

    async fn load_envelopes(
        self: &Arc<Self>,
        block_roots: &[Hash256],
    ) -> Result<Vec<(Hash256, PayloadEnvelopeResult<T::EthSpec>)>, BeaconChainError> {
        let streamer = self.clone();
        let block_roots = block_roots.to_vec();
        let split_slot = streamer.adapter.get_split_slot();
        // Loading from the DB is slow -> spawn a blocking task
        self.adapter
            .executor()
            .spawn_blocking_handle(
                move || {
                    let mut results: Vec<(Hash256, PayloadEnvelopeResult<T::EthSpec>)> = Vec::new();
                    for root in block_roots.iter() {
                        // TODO(gloas) we are loading the full envelope from the db.
                        // in a future PR we will only be storing the blinded envelope.
                        // When that happens we'll need to use the EL here to fetch
                        // the payload and reconstruct the non-blinded envelope.
                        let opt_envelope = match streamer.load_envelope(root) {
                            Ok(opt_envelope) => opt_envelope,
                            Err(e) => {
                                results.push((*root, Err(e)));
                                continue;
                            }
                        };

                        if streamer.request_source == EnvelopeRequestSource::ByRoot {
                            // No envelope verification required for `ENVELOPE_BY_ROOT` requests.
                            // If we only served envelopes that match our canonical view, nodes
                            // wouldn't be able to sync other branches.
                            results.push((*root, Ok(opt_envelope)));
                            continue;
                        }

                        // When loading envelopes on or after the split slot, we must cross reference the bid from the child beacon block.
                        // There can be payloads that have been imported into the hot db but don't match our current view
                        // of the canonical chain.

                        if let Some(envelope) = opt_envelope {
                            // Ensure that the envelopes we're serving match our view of the canonical chain.

                            // When loading envelopes before the split slot, there is no need to check.
                            // Non-canonical payload envelopes will have already been pruned.
                            if split_slot > envelope.slot() {
                                results.push((*root, Ok(Some(envelope))));
                                continue;
                            }

                            match streamer.adapter.block_has_canonical_payload(root) {
                                Ok(is_envelope_canonical) => {
                                    if is_envelope_canonical {
                                        results.push((*root, Ok(Some(envelope))));
                                    } else {
                                        results.push((*root, Ok(None)));
                                    }
                                }
                                Err(_) => {
                                    results.push((
                                        *root,
                                        Err(BeaconChainError::EnvelopeStreamerError(
                                            Error::BlockMissingFromForkChoice,
                                        )),
                                    ));
                                }
                            }
                        } else {
                            results.push((*root, Ok(None)));
                        }
                    }
                    results
                },
                "load_execution_payload_envelopes",
            )
            .ok_or(BeaconChainError::RuntimeShutdown)?
            .await
            .map_err(BeaconChainError::TokioJoin)
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
        block_roots: Vec<Hash256>,
    ) -> impl Stream<Item = (Hash256, Arc<PayloadEnvelopeResult<T::EthSpec>>)> {
        let (envelope_tx, envelope_rx) = mpsc::unbounded_channel();
        debug!(
            envelopes = block_roots.len(),
            "Launching a PayloadEnvelopeStreamer"
        );
        let executor = self.adapter.executor().clone();
        executor.spawn(
            self.stream_payload_envelopes(block_roots, envelope_tx),
            "get_payload_envelopes_sender",
        );
        UnboundedReceiverStream::new(envelope_rx)
    }
}

/// Create a `PayloadEnvelopeStreamer` from a `BeaconChain` and launch a stream.
#[cfg(not(test))]
pub fn launch_payload_envelope_stream<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_roots: Vec<Hash256>,
    request_source: EnvelopeRequestSource,
) -> impl Stream<Item = (Hash256, Arc<PayloadEnvelopeResult<T::EthSpec>>)> {
    let adapter = beacon_chain_adapter::EnvelopeStreamerBeaconAdapter::new(chain);
    PayloadEnvelopeStreamer::new(adapter, request_source).launch_stream(block_roots)
}

async fn send_errors<E: EthSpec>(
    block_roots: &[Hash256],
    sender: UnboundedSender<(Hash256, Arc<PayloadEnvelopeResult<E>>)>,
    beacon_chain_error: BeaconChainError,
) {
    let result = Arc::new(Err(beacon_chain_error));
    for beacon_block_root in block_roots {
        if sender.send((*beacon_block_root, result.clone())).is_err() {
            error!("EnvelopeStreamer channel closed unexpectedly");
            break;
        }
    }
}
