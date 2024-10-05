use crate::rpc::{Protocol, RpcResponse, SubstreamId};
use crate::PeerId;
use libp2p::swarm::ConnectionId;
use std::collections::{HashMap, VecDeque};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio_util::time::DelayQueue;
use types::EthSpec;

#[derive(Clone)]
pub(super) struct QueuedResponse<E: EthSpec> {
    pub peer_id: PeerId,
    pub connection_id: ConnectionId,
    pub substream_id: SubstreamId,
    pub response: RpcResponse<E>,
    pub protocol: Protocol,
}

pub(super) struct DelayedResponses<E: EthSpec> {
    responses: HashMap<(PeerId, Protocol), VecDeque<QueuedResponse<E>>>,
    next_response: DelayQueue<(PeerId, Protocol)>,
}

impl<E: EthSpec> DelayedResponses<E> {
    pub fn new() -> Self {
        DelayedResponses {
            responses: HashMap::new(),
            next_response: DelayQueue::new(),
        }
    }

    pub fn exists(&self, peer_id: PeerId, protocol: Protocol) -> bool {
        let Some(responses) = self.responses.get(&(peer_id, protocol)) else {
            return false;
        };

        !responses.is_empty()
    }

    pub fn remove(&mut self, peer_id: PeerId, protocol: Protocol) {
        self.responses.remove(&(peer_id, protocol));
    }

    /// Add a response to the queue. Note that this method requires other responses with the same
    /// protocol to already exist in the queue.
    /// Use `insert` instead if you’re unsure whether responses already exist.
    ///
    /// Unlike `push_back`, this method doesn't insert a `Protocol` into  `self.next_response` because
    /// there is no `wait_time`.
    /// No issues (e.g., the queued response never being consumed) occur, because `add` requires
    /// that other responses of the same protocol already exist in the queue so the queued response
    /// is always consumed (and will be re-queued if the limiter doesn't allow it, via `push_front` with
    /// `wait_time`).
    pub fn add(
        &mut self,
        peer_id: PeerId,
        protocol: Protocol,
        connection_id: ConnectionId,
        substream_id: SubstreamId,
        response: RpcResponse<E>,
    ) {
        self.responses
            .get_mut(&(peer_id, protocol))
            .expect("DelayedResponses should exist")
            .push_back(QueuedResponse {
                peer_id,
                connection_id,
                substream_id,
                response,
                protocol,
            });
    }

    pub fn push_back(
        &mut self,
        peer_id: PeerId,
        protocol: Protocol,
        connection_id: ConnectionId,
        substream_id: SubstreamId,
        response: RpcResponse<E>,
        wait_time: Duration,
    ) {
        self.responses
            .entry((peer_id, protocol))
            .or_default()
            .push_back(QueuedResponse {
                peer_id,
                connection_id,
                substream_id,
                response,
                protocol,
            });
        self.next_response.insert((peer_id, protocol), wait_time);
    }

    pub fn push_front(&mut self, response: QueuedResponse<E>, wait_time: Duration) {
        self.next_response
            .insert((response.peer_id, response.protocol), wait_time);
        self.responses
            .entry((response.peer_id, response.protocol))
            .or_default()
            .push_front(response);
    }

    pub fn poll_next_response(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Option<&mut VecDeque<QueuedResponse<E>>> {
        if let Poll::Ready(Some(expired)) = self.next_response.poll_expired(cx) {
            let (peer_id, protocol) = expired.into_inner();
            if let Some(r) = self.responses.get_mut(&(peer_id, protocol)) {
                return Some(r);
            }
        }
        None
    }
}
