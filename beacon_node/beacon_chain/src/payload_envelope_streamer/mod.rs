mod beacon_chain_adapter;
#[cfg(test)]
mod tests;

use std::sync::Arc;

#[cfg_attr(test, double)]
use crate::payload_envelope_streamer::beacon_chain_adapter::EnvelopeStreamerBeaconAdapter;
use execution_layer::ExecutionPayloadBodyV2;
use futures::Stream;
#[cfg(test)]
use mockall_double::double;
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::{debug, error, warn};
use types::{
    EthSpec, ExecutionBlockHash, ExecutionPayloadGloas, ExecutionPayloadRef, ExecutionRequestsRef,
    Hash256, SignedExecutionPayloadEnvelope, SignedExecutionPayloadEnvelopeSummary, Slot,
};

#[cfg(not(test))]
use crate::BeaconChain;
use crate::{BeaconChainError, BeaconChainTypes};

type PayloadEnvelopeResult<E> =
    Result<Option<Arc<SignedExecutionPayloadEnvelope<E>>>, BeaconChainError>;

#[derive(Debug)]
pub enum Error {
    PayloadMissingFromExecutionLayer(ExecutionBlockHash),
    PayloadBodiesByHashV2Failure(Box<execution_layer::Error>),
    InvalidPayloadBodiesResponse {
        expected: usize,
        received: usize,
    },
    PayloadBodyMissingWithdrawals(ExecutionBlockHash),
    PayloadBodyMissingBlockAccessList(ExecutionBlockHash),
    SummaryBlockRootMismatch {
        requested: Hash256,
        summary: Hash256,
    },
    PayloadHashMismatch {
        expected: ExecutionBlockHash,
        received: ExecutionBlockHash,
    },
    ComputedPayloadHashMismatch {
        expected: ExecutionBlockHash,
        computed: ExecutionBlockHash,
    },
}

#[derive(Debug, PartialEq)]
pub enum EnvelopeRequestSource {
    ByRoot,
    ByRange,
}

enum LoadedEnvelope<E: EthSpec> {
    Complete(PayloadEnvelopeResult<E>),
    NeedsPayload(Box<SignedExecutionPayloadEnvelopeSummary<E>>),
}

impl<E: EthSpec> LoadedEnvelope<E> {
    fn slot(&self) -> Option<Slot> {
        match self {
            Self::Complete(Ok(Some(envelope))) => Some(envelope.slot()),
            Self::NeedsPayload(summary) => Some(summary.slot()),
            Self::Complete(Ok(None) | Err(_)) => None,
        }
    }
}

pub struct PayloadEnvelopeStreamer<T: BeaconChainTypes> {
    adapter: EnvelopeStreamerBeaconAdapter<T>,
    request_source: EnvelopeRequestSource,
}

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

    /// Load the envelope summary and its locally retained payload from the database.
    ///
    /// A summary whose payload has been pruned is returned as `NeedsPayload` for reconstruction
    /// from the execution layer.
    fn load_envelope(&self, beacon_block_root: &Hash256) -> LoadedEnvelope<T::EthSpec> {
        let summary = match self.adapter.get_payload_envelope_summary(beacon_block_root) {
            Ok(Some(summary)) => summary,
            Ok(None) => return LoadedEnvelope::Complete(Ok(None)),
            Err(error) => {
                return LoadedEnvelope::Complete(Err(BeaconChainError::DBError(error)));
            }
        };

        if summary.beacon_block_root != *beacon_block_root {
            return LoadedEnvelope::Complete(Err(Error::SummaryBlockRootMismatch {
                requested: *beacon_block_root,
                summary: summary.beacon_block_root,
            }
            .into()));
        }

        match self.adapter.get_envelope_payload(beacon_block_root) {
            Ok(Some(payload)) => LoadedEnvelope::Complete(reconstruct_envelope(summary, payload)),
            Ok(None) => LoadedEnvelope::NeedsPayload(Box::new(summary)),
            Err(error) => LoadedEnvelope::Complete(Err(BeaconChainError::DBError(error))),
        }
    }

    async fn load_envelopes(
        self: &Arc<Self>,
        block_roots: &[Hash256],
    ) -> Result<Vec<(Hash256, Arc<PayloadEnvelopeResult<T::EthSpec>>)>, BeaconChainError> {
        let streamer = self.clone();
        let block_roots = block_roots.to_vec();
        let split_slot = streamer.adapter.get_split_slot();
        // Loading from the DB is slow -> spawn a blocking task
        let loaded_envelopes = self
            .adapter
            .executor()
            .spawn_blocking_handle(
                move || {
                    block_roots
                        .into_iter()
                        .map(|root| {
                            let loaded = streamer.load_envelope(&root);

                            // By-root requests may sync branches other than our canonical view.
                            if streamer.request_source == EnvelopeRequestSource::ByRoot {
                                return (root, loaded);
                            }

                            let Some(slot) = loaded.slot() else {
                                return (root, loaded);
                            };

                            // Before the split, non-canonical envelopes have already been pruned.
                            if split_slot > slot {
                                return (root, loaded);
                            }

                            match streamer.adapter.block_has_canonical_payload(&root) {
                                Ok(true) => (root, loaded),
                                Ok(false) => (root, LoadedEnvelope::Complete(Ok(None))),
                                Err(error) => (root, LoadedEnvelope::Complete(Err(error))),
                            }
                        })
                        .collect::<Vec<_>>()
                },
                "load_execution_payload_envelopes",
            )
            .ok_or(BeaconChainError::RuntimeShutdown)?
            .await
            .map_err(BeaconChainError::TokioJoin)?;

        let payload_requests = loaded_envelopes
            .iter()
            .filter_map(|(_, loaded)| match loaded {
                LoadedEnvelope::NeedsPayload(summary) => Some(summary.block_hash()),
                LoadedEnvelope::Complete(_) => None,
            })
            .collect::<Vec<_>>();

        let mut payload_bodies = match self.fetch_payload_bodies(payload_requests).await {
            Ok(payload_bodies) => Ok(payload_bodies.into_iter()),
            Err(error) => Err(Arc::new(Err(error))),
        };

        Ok(loaded_envelopes
            .into_iter()
            .map(|(root, loaded)| {
                let result = match loaded {
                    LoadedEnvelope::Complete(result) => Arc::new(result),
                    LoadedEnvelope::NeedsPayload(summary) => match &mut payload_bodies {
                        Ok(payload_bodies) => Arc::new(match payload_bodies.next().flatten() {
                            Some(payload_body) => {
                                reconstruct_envelope_from_body(*summary, payload_body)
                            }
                            None => Err(Error::PayloadMissingFromExecutionLayer(
                                summary.block_hash(),
                            )
                            .into()),
                        }),
                        Err(error) => error.clone(),
                    },
                };
                (root, result)
            })
            .collect())
    }

    /// Fetch Gloas payload bodies using `engine_getPayloadBodiesByHashV2`.
    ///
    /// The returned vector has the same length and order as `block_hashes`. An unknown body is
    /// represented by `None`.
    async fn fetch_payload_bodies(
        &self,
        block_hashes: Vec<ExecutionBlockHash>,
    ) -> Result<Vec<Option<ExecutionPayloadBodyV2>>, BeaconChainError> {
        let mut payload_bodies = Vec::with_capacity(block_hashes.len());
        for chunk in block_hashes.chunks(MAX_PAYLOAD_BODIES_PER_REQUEST) {
            let chunk_payload_bodies = self
                .adapter
                .get_payload_bodies_by_hash_v2(chunk.to_vec())
                .await?;
            if chunk_payload_bodies.len() != chunk.len() {
                return Err(Error::InvalidPayloadBodiesResponse {
                    expected: chunk.len(),
                    received: chunk_payload_bodies.len(),
                }
                .into());
            }
            payload_bodies.extend(chunk_payload_bodies);
        }
        Ok(payload_bodies)
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
            if sender.send((root, result)).is_err() {
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

/// The Engine API only guarantees support for 32 hashes per payload-body request.
const MAX_PAYLOAD_BODIES_PER_REQUEST: usize = 32;

fn reconstruct_envelope<E: EthSpec>(
    summary: SignedExecutionPayloadEnvelopeSummary<E>,
    payload: ExecutionPayloadGloas<E>,
) -> PayloadEnvelopeResult<E> {
    let expected_payload_hash = summary.block_hash();
    if expected_payload_hash != payload.block_hash {
        return Err(Error::PayloadHashMismatch {
            expected: expected_payload_hash,
            received: payload.block_hash,
        }
        .into());
    }

    reconstruct_envelope_from_body(
        summary,
        ExecutionPayloadBodyV2 {
            transactions: payload.transactions,
            withdrawals: Some(payload.withdrawals),
            block_access_list: Some(payload.block_access_list),
        },
    )
}

fn reconstruct_envelope_from_body<E: EthSpec>(
    summary: SignedExecutionPayloadEnvelopeSummary<E>,
    payload_body: ExecutionPayloadBodyV2,
) -> PayloadEnvelopeResult<E> {
    let expected_payload_hash = summary.block_hash();
    let withdrawals = payload_body
        .withdrawals
        .ok_or(Error::PayloadBodyMissingWithdrawals(expected_payload_hash))?;
    let block_access_list =
        payload_body
            .block_access_list
            .ok_or(Error::PayloadBodyMissingBlockAccessList(
                expected_payload_hash,
            ))?;
    let envelope = summary.into_envelope_from_payload_body(
        payload_body.transactions,
        withdrawals,
        block_access_list,
    );
    let (computed_payload_hash, _) = execution_layer::calculate_execution_block_hash(
        ExecutionPayloadRef::Gloas(&envelope.message.payload),
        Some(envelope.message.parent_beacon_block_root),
        Some(ExecutionRequestsRef::Gloas(
            &envelope.message.execution_requests,
        )),
    );
    if expected_payload_hash != computed_payload_hash {
        return Err(Error::ComputedPayloadHashMismatch {
            expected: expected_payload_hash,
            computed: computed_payload_hash,
        }
        .into());
    }

    Ok(Some(Arc::new(envelope)))
}

impl From<Error> for BeaconChainError {
    fn from(error: Error) -> Self {
        BeaconChainError::EnvelopeStreamerError(error)
    }
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
