use std::{collections::hash_map::Entry, hash::Hash};

use beacon_chain::validator_monitor::timestamp_now;
use fnv::FnvHashMap;
use lighthouse_network::PeerId;
use strum::IntoStaticStr;
use types::Hash256;

pub use blobs_by_root::{BlobsByRootRequestItems, BlobsByRootSingleBlockRequest};
pub use blocks_by_root::{BlocksByRootRequestItems, BlocksByRootSingleRequest};
pub use data_columns_by_root::{
    DataColumnsByRootRequestItems, DataColumnsByRootSingleBlockRequest,
};

use crate::metrics;

use super::{RpcEvent, RpcResponseResult};

mod blobs_by_root;
mod blocks_by_root;
mod data_columns_by_root;

#[derive(Debug, PartialEq, Eq, IntoStaticStr)]
pub enum LookupVerifyError {
    NotEnoughResponsesReturned { actual: usize },
    TooManyResponses,
    UnrequestedBlockRoot(Hash256),
    UnrequestedIndex(u64),
    InvalidInclusionProof,
    DuplicateData,
}

/// Collection of active requests of a single ReqResp method, i.e. `blocks_by_root`
pub struct ActiveRequests<K: Eq + Hash, T: ActiveRequestItems> {
    requests: FnvHashMap<K, ActiveRequest<T>>,
    name: &'static str,
}

/// Stateful container for a single active ReqResp request
struct ActiveRequest<T: ActiveRequestItems> {
    state: State<T>,
    peer_id: PeerId,
    // Error if the request terminates before receiving max expected responses
    expect_max_responses: bool,
}

enum State<T> {
    Active(T),
    CompletedEarly,
    Errored,
}

impl<K: Eq + Hash, T: ActiveRequestItems> ActiveRequests<K, T> {
    pub fn new(name: &'static str) -> Self {
        Self {
            requests: <_>::default(),
            name,
        }
    }

    pub fn insert(&mut self, id: K, peer_id: PeerId, expect_max_responses: bool, items: T) {
        self.requests.insert(
            id,
            ActiveRequest {
                state: State::Active(items),
                peer_id,
                expect_max_responses,
            },
        );
    }

    /// Handle an `RpcEvent` for a specific request index by `id`.
    ///
    /// Lighthouse ReqResp protocol API promises to send 0 or more `RpcEvent::Response` chunks,
    /// and EITHER a single `RpcEvent::RPCError` or RpcEvent::StreamTermination.
    ///
    /// Downstream code expects to receive a single `Result` value per request ID. However,
    /// `add_item` may convert ReqResp success chunks into errors. This function handles the
    /// multiple errors / stream termination internally ensuring that a single `Some<Result>` is
    /// returned.
    pub fn on_response(
        &mut self,
        id: K,
        rpc_event: RpcEvent<T::Item>,
    ) -> Option<RpcResponseResult<Vec<T::Item>>> {
        let Entry::Occupied(mut entry) = self.requests.entry(id) else {
            metrics::inc_counter_vec(&metrics::SYNC_UNKNOWN_NETWORK_REQUESTS, &[self.name]);
            return None;
        };

        match rpc_event {
            // Handler of a success ReqResp chunk. Adds the item to the request accumulator.
            // `ActiveRequestItems` validates the item before appending to its internal state.
            RpcEvent::Response(item, seen_timestamp) => {
                let request = &mut entry.get_mut();
                match &mut request.state {
                    State::Active(items) => {
                        match items.add(item) {
                            // Received all items we are expecting for, return early, but keep the request
                            // struct to handle the stream termination gracefully.
                            Ok(true) => {
                                let items = items.consume();
                                request.state = State::CompletedEarly;
                                Some(Ok((items, seen_timestamp)))
                            }
                            // Received item, but we are still expecting more
                            Ok(false) => None,
                            // Received an invalid item
                            Err(e) => {
                                request.state = State::Errored;
                                Some(Err(e.into()))
                            }
                        }
                    }
                    // Should never happen, ReqResp network behaviour enforces a max count of chunks
                    // When `max_remaining_chunks <= 1` a the inbound stream in terminated in
                    // `rpc/handler.rs`. Handling this case adds complexity for no gain. Even if an
                    // attacker could abuse this, there's no gain in sending garbage chunks that
                    // will be ignored anyway.
                    State::CompletedEarly => None,
                    // Ignore items after errors. We may want to penalize repeated invalid chunks
                    // for the same response. But that's an optimization to ban peers sending
                    // invalid data faster that we choose to not adopt for now.
                    State::Errored => None,
                }
            }
            RpcEvent::StreamTermination => {
                // After stream termination we must forget about this request, there will be no more
                // messages coming from the network
                let request = entry.remove();
                match request.state {
                    // Received a stream termination in a valid sequence, consume items
                    State::Active(mut items) => {
                        if request.expect_max_responses {
                            Some(Err(LookupVerifyError::NotEnoughResponsesReturned {
                                actual: items.consume().len(),
                            }
                            .into()))
                        } else {
                            Some(Ok((items.consume(), timestamp_now())))
                        }
                    }
                    // Items already returned, ignore stream termination
                    State::CompletedEarly => None,
                    // Returned an error earlier, ignore stream termination
                    State::Errored => None,
                }
            }
            RpcEvent::RPCError(e) => {
                // After an Error event from the network we must forget about this request as this
                // may be the last message for this request.
                match entry.remove().state {
                    // Received error while request is still active, propagate error.
                    State::Active(_) => Some(Err(e.into())),
                    // Received error after completing the request, ignore the error. This is okay
                    // because the network has already registered a downscore event if necessary for
                    // this message.
                    State::CompletedEarly => None,
                    // Received a network error after a validity error. Okay to ignore, see above
                    State::Errored => None,
                }
            }
        }
    }

    pub fn active_requests_of_peer(&self, peer_id: &PeerId) -> Vec<&K> {
        self.requests
            .iter()
            .filter(|(_, request)| &request.peer_id == peer_id)
            .map(|(id, _)| id)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.requests.len()
    }
}

pub trait ActiveRequestItems {
    type Item;

    /// Add a new item into the accumulator. Returns true if all expected items have been received.
    fn add(&mut self, item: Self::Item) -> Result<bool, LookupVerifyError>;

    /// Return all accumulated items consuming them.
    fn consume(&mut self) -> Vec<Self::Item>;
}
