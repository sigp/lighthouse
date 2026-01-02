use super::{
    BehaviourAction, MAX_CONCURRENT_REQUESTS, Protocol, RPCSend, ReqId, RequestType,
    config::OutboundRateLimiterConfig,
    rate_limiter::{RPCRateLimiter as RateLimiter, RateLimitedErr},
};
use crate::rpc::rate_limiter::RateLimiterItem;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    collections::{HashMap, VecDeque, hash_map::Entry},
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use futures::FutureExt;
use libp2p::{PeerId, swarm::NotifyHandler};
use logging::crit;
use smallvec::SmallVec;
use tokio_util::time::DelayQueue;
use tracing::debug;
use types::{EthSpec, ForkContext};

/// A request that was rate limited or waiting on rate limited requests for the same peer and
/// protocol.
struct QueuedRequest<Id: ReqId, E: EthSpec> {
    req: RequestType<E>,
    request_id: Id,
    queued_at: Duration,
}

/// The number of milliseconds requests delayed due to the concurrent request limit stay in the queue.
const WAIT_TIME_DUE_TO_CONCURRENT_REQUESTS: u64 = 100;

#[allow(clippy::type_complexity)]
pub(crate) struct SelfRateLimiter<Id: ReqId, E: EthSpec> {
    /// Active requests that are awaiting a response.
    active_requests: HashMap<PeerId, HashMap<Protocol, usize>>,
    /// Requests queued for sending per peer. These requests are stored when the self rate
    /// limiter rejects them. Rate limiting is based on a Peer and Protocol basis, therefore
    /// are stored in the same way.
    delayed_requests: HashMap<(PeerId, Protocol), VecDeque<QueuedRequest<Id, E>>>,
    /// The delay required to allow a peer's outbound request per protocol.
    next_peer_request: DelayQueue<(PeerId, Protocol)>,
    /// Rate limiter for our own requests.
    rate_limiter: Option<RateLimiter>,
    /// Requests that are ready to be sent.
    ready_requests: SmallVec<[(PeerId, RPCSend<Id, E>, Duration); 3]>,
}

/// Error returned when the rate limiter does not accept a request.
// NOTE: this is currently not used, but might be useful for debugging.
pub enum Error {
    /// There are queued requests for this same peer and protocol.
    PendingRequests,
    /// Request was tried but rate limited.
    RateLimited,
}

impl<Id: ReqId, E: EthSpec> SelfRateLimiter<Id, E> {
    /// Creates a new [`SelfRateLimiter`] based on configuration values.
    pub fn new(
        config: Option<OutboundRateLimiterConfig>,
        fork_context: Arc<ForkContext>,
    ) -> Result<Self, &'static str> {
        debug!(?config, "Using self rate limiting params");
        let rate_limiter = if let Some(c) = config {
            Some(RateLimiter::new_with_config(c.0, fork_context)?)
        } else {
            None
        };

        Ok(SelfRateLimiter {
            active_requests: Default::default(),
            delayed_requests: Default::default(),
            next_peer_request: Default::default(),
            rate_limiter,
            ready_requests: Default::default(),
        })
    }

    /// Checks if the rate limiter allows the request. If it's allowed, returns the
    /// [`ToSwarm`] that should be emitted. When not allowed, the request is delayed
    /// until it can be sent.
    pub fn allows(
        &mut self,
        peer_id: PeerId,
        request_id: Id,
        req: RequestType<E>,
    ) -> Result<RPCSend<Id, E>, Error> {
        let protocol = req.versioned_protocol().protocol();
        // First check that there are not already other requests waiting to be sent.
        if let Some(queued_requests) = self.delayed_requests.get_mut(&(peer_id, protocol)) {
            debug!(%peer_id, protocol = %req.protocol(), "Self rate limiting since there are already other requests waiting to be sent");
            queued_requests.push_back(QueuedRequest {
                req,
                request_id,
                queued_at: timestamp_now(),
            });
            return Err(Error::PendingRequests);
        }
        match Self::try_send_request(
            &mut self.active_requests,
            &mut self.rate_limiter,
            peer_id,
            request_id,
            req,
        ) {
            Err((rate_limited_req, wait_time)) => {
                let key = (peer_id, protocol);
                self.next_peer_request.insert(key, wait_time);
                self.delayed_requests
                    .entry(key)
                    .or_default()
                    .push_back(rate_limited_req);

                Err(Error::RateLimited)
            }
            Ok(event) => Ok(event),
        }
    }

    /// Auxiliary function to deal with self rate limiting outcomes. If the rate limiter allows the
    /// request, the [`ToSwarm`] that should be emitted is returned. If the request
    /// should be delayed, it's returned with the duration to wait.
    #[allow(clippy::result_large_err)]
    fn try_send_request(
        active_requests: &mut HashMap<PeerId, HashMap<Protocol, usize>>,
        rate_limiter: &mut Option<RateLimiter>,
        peer_id: PeerId,
        request_id: Id,
        req: RequestType<E>,
    ) -> Result<RPCSend<Id, E>, (QueuedRequest<Id, E>, Duration)> {
        if let Some(active_request) = active_requests.get(&peer_id)
            && let Some(count) = active_request.get(&req.protocol())
            && *count >= MAX_CONCURRENT_REQUESTS
        {
            debug!(
                %peer_id,
                protocol = %req.protocol(),
                "Self rate limiting due to the number of concurrent requests"
            );
            return Err((
                QueuedRequest {
                    req,
                    request_id,
                    queued_at: timestamp_now(),
                },
                Duration::from_millis(WAIT_TIME_DUE_TO_CONCURRENT_REQUESTS),
            ));
        }

        if let Some(limiter) = rate_limiter.as_mut() {
            match limiter.allows(&peer_id, &req) {
                Ok(()) => {}
                Err(e) => {
                    let protocol = req.versioned_protocol();
                    match e {
                        RateLimitedErr::TooLarge => {
                            // this should never happen with default parameters. Let's just send the request.
                            // Log a crit since this is a config issue.
                            crit!(
                                protocol = %req.versioned_protocol().protocol(),
                                "Self rate limiting error for a batch that will never fit. Sending request anyway. Check configuration parameters.",
                            );
                        }
                        RateLimitedErr::TooSoon(wait_time) => {
                            debug!(protocol = %protocol.protocol(), wait_time_ms = wait_time.as_millis(), %peer_id, "Self rate limiting");
                            return Err((
                                QueuedRequest {
                                    req,
                                    request_id,
                                    queued_at: timestamp_now(),
                                },
                                wait_time,
                            ));
                        }
                    }
                }
            }
        }

        *active_requests
            .entry(peer_id)
            .or_default()
            .entry(req.protocol())
            .or_default() += 1;

        Ok(RPCSend::Request(request_id, req))
    }

    /// When a peer and protocol are allowed to send a next request, this function checks the
    /// queued requests and attempts marking as ready as many as the limiter allows.
    fn next_peer_request_ready(&mut self, peer_id: PeerId, protocol: Protocol) {
        if let Entry::Occupied(mut entry) = self.delayed_requests.entry((peer_id, protocol)) {
            let queued_requests = entry.get_mut();
            while let Some(QueuedRequest {
                req,
                request_id,
                queued_at,
            }) = queued_requests.pop_front()
            {
                match Self::try_send_request(
                    &mut self.active_requests,
                    &mut self.rate_limiter,
                    peer_id,
                    request_id,
                    req.clone(),
                ) {
                    Err((_rate_limited_req, wait_time)) => {
                        let key = (peer_id, protocol);
                        self.next_peer_request.insert(key, wait_time);
                        // Don't push `rate_limited_req` here to prevent `queued_at` from being updated.
                        queued_requests.push_front(QueuedRequest {
                            req,
                            request_id,
                            queued_at,
                        });
                        // If one fails just wait for the next window that allows sending requests.
                        return;
                    }
                    Ok(event) => self.ready_requests.push((peer_id, event, queued_at)),
                }
            }
            if queued_requests.is_empty() {
                entry.remove();
            }
        }
        // NOTE: There can be entries that have been removed due to peer disconnections, we simply
        // ignore these messages here.
    }

    /// Informs the limiter that a peer has disconnected. This removes any pending requests and
    /// returns their IDs.
    pub fn peer_disconnected(&mut self, peer_id: PeerId) -> Vec<(Id, Protocol)> {
        self.active_requests.remove(&peer_id);

        // It's not ideal to iterate this map, but the key is (PeerId, Protocol) and this map
        // should never really be large. So we iterate for simplicity
        let mut failed_requests = Vec::new();
        self.delayed_requests
            .retain(|(map_peer_id, protocol), queue| {
                if map_peer_id == &peer_id {
                    // NOTE: Currently cannot remove entries from the DelayQueue, we will just let
                    // them expire and ignore them.
                    for message in queue {
                        failed_requests.push((message.request_id, *protocol))
                    }
                    // Remove the entry
                    false
                } else {
                    // Keep the entry
                    true
                }
            });
        failed_requests
    }

    /// Informs the limiter that a response has been received.
    pub fn request_completed(&mut self, peer_id: &PeerId, protocol: Protocol) {
        if let Some(active_requests) = self.active_requests.get_mut(peer_id)
            && let Entry::Occupied(mut entry) = active_requests.entry(protocol)
        {
            if *entry.get() > 1 {
                *entry.get_mut() -= 1;
            } else {
                entry.remove();
            }
        }
    }

    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<BehaviourAction<Id, E>> {
        // First check the requests that were self rate limited, since those might add events to
        // the queue. Also do this before rate limiter pruning to avoid removing and
        // immediately adding rate limiting keys.
        if let Poll::Ready(Some(expired)) = self.next_peer_request.poll_expired(cx) {
            let (peer_id, protocol) = expired.into_inner();
            self.next_peer_request_ready(peer_id, protocol);
        }

        // Prune the rate limiter.
        if let Some(limiter) = self.rate_limiter.as_mut() {
            let _ = limiter.poll_unpin(cx);
        }

        // Finally return any queued events.
        if let Some((peer_id, event, queued_at)) = self.ready_requests.pop() {
            metrics::observe_duration(
                &crate::metrics::OUTBOUND_REQUEST_IDLING,
                timestamp_now().saturating_sub(queued_at),
            );
            return Poll::Ready(BehaviourAction::NotifyHandler {
                peer_id,
                handler: NotifyHandler::Any,
                event,
            });
        }

        Poll::Pending
    }
}

/// Returns the duration since the unix epoch.
pub fn timestamp_now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
}

#[cfg(test)]
mod tests {
    use crate::rpc::config::{OutboundRateLimiterConfig, RateLimiterConfig};
    use crate::rpc::rate_limiter::Quota;
    use crate::rpc::self_limiter::SelfRateLimiter;
    use crate::rpc::{Ping, Protocol, RPCSend, RequestType};
    use crate::service::api_types::{AppRequestId, SingleLookupReqId, SyncRequestId};
    use libp2p::PeerId;
    use logging::create_test_tracing_subscriber;
    use std::num::NonZeroU64;
    use std::time::Duration;
    use types::{EthSpec, ForkContext, Hash256, MainnetEthSpec, Slot};

    /// Test that `next_peer_request_ready` correctly maintains the queue.
    #[tokio::test]
    async fn test_next_peer_request_ready() {
        create_test_tracing_subscriber();
        let config = OutboundRateLimiterConfig(RateLimiterConfig {
            ping_quota: Quota::n_every(NonZeroU64::new(1).unwrap(), 2),
            ..Default::default()
        });
        let fork_context = std::sync::Arc::new(ForkContext::new::<MainnetEthSpec>(
            Slot::new(0),
            Hash256::ZERO,
            &MainnetEthSpec::default_spec(),
        ));
        let mut limiter: SelfRateLimiter<AppRequestId, MainnetEthSpec> =
            SelfRateLimiter::new(Some(config), fork_context).unwrap();
        let peer_id = PeerId::random();
        let lookup_id = 0;

        for i in 1..=5u32 {
            let _ = limiter.allows(
                peer_id,
                AppRequestId::Sync(SyncRequestId::SingleBlock {
                    id: SingleLookupReqId {
                        lookup_id,
                        req_id: i,
                    },
                }),
                RequestType::Ping(Ping { data: i as u64 }),
            );
        }

        {
            let queue = limiter
                .delayed_requests
                .get(&(peer_id, Protocol::Ping))
                .unwrap();
            assert_eq!(4, queue.len());

            // Check that requests in the queue are ordered in the sequence 2, 3, 4, 5.
            let mut iter = queue.iter();
            for i in 2..=5u32 {
                assert!(matches!(
                    iter.next().unwrap().request_id,
                    AppRequestId::Sync(SyncRequestId::SingleBlock {
                        id: SingleLookupReqId { req_id, .. },
                    }) if req_id == i,
                ));
            }

            assert_eq!(limiter.ready_requests.len(), 0);
        }

        // Wait until the tokens have been regenerated, then run `next_peer_request_ready`.
        tokio::time::sleep(Duration::from_secs(3)).await;
        limiter.next_peer_request_ready(peer_id, Protocol::Ping);

        {
            let queue = limiter
                .delayed_requests
                .get(&(peer_id, Protocol::Ping))
                .unwrap();
            assert_eq!(3, queue.len());

            // Check that requests in the queue are ordered in the sequence 3, 4, 5.
            let mut iter = queue.iter();
            for i in 3..=5 {
                assert!(matches!(
                    iter.next().unwrap().request_id,
                    AppRequestId::Sync(SyncRequestId::SingleBlock {
                        id: SingleLookupReqId { req_id, .. },
                    }) if req_id == i,
                ));
            }

            assert_eq!(limiter.ready_requests.len(), 1);
        }
    }

    /// Test that `next_peer_request_ready` correctly maintains the queue when using the self-limiter without rate limiting.
    #[tokio::test]
    async fn test_next_peer_request_ready_concurrent_requests() {
        let fork_context = std::sync::Arc::new(ForkContext::new::<MainnetEthSpec>(
            Slot::new(0),
            Hash256::ZERO,
            &MainnetEthSpec::default_spec(),
        ));
        let mut limiter: SelfRateLimiter<AppRequestId, MainnetEthSpec> =
            SelfRateLimiter::new(None, fork_context).unwrap();
        let peer_id = PeerId::random();

        for i in 1..=5u32 {
            let result = limiter.allows(
                peer_id,
                AppRequestId::Sync(SyncRequestId::SingleBlock {
                    id: SingleLookupReqId {
                        lookup_id: i,
                        req_id: i,
                    },
                }),
                RequestType::Ping(Ping { data: i as u64 }),
            );

            // Check that the limiter allows the first two requests.
            if i <= 2 {
                assert!(result.is_ok());
            } else {
                assert!(result.is_err());
            }
        }

        let queue = limiter
            .delayed_requests
            .get(&(peer_id, Protocol::Ping))
            .unwrap();
        assert_eq!(3, queue.len());

        // The delayed requests remain even after the next_peer_request_ready call because the responses have not been received.
        limiter.next_peer_request_ready(peer_id, Protocol::Ping);
        let queue = limiter
            .delayed_requests
            .get(&(peer_id, Protocol::Ping))
            .unwrap();
        assert_eq!(3, queue.len());

        limiter.request_completed(&peer_id, Protocol::Ping);
        limiter.next_peer_request_ready(peer_id, Protocol::Ping);

        let queue = limiter
            .delayed_requests
            .get(&(peer_id, Protocol::Ping))
            .unwrap();
        assert_eq!(2, queue.len());

        limiter.request_completed(&peer_id, Protocol::Ping);
        limiter.request_completed(&peer_id, Protocol::Ping);
        limiter.next_peer_request_ready(peer_id, Protocol::Ping);

        let queue = limiter.delayed_requests.get(&(peer_id, Protocol::Ping));
        assert!(queue.is_none());

        // Check that the three delayed requests have moved to ready_requests.
        let mut it = limiter.ready_requests.iter();
        for i in 3..=5u32 {
            let (_peer_id, RPCSend::Request(request_id, _), _) = it.next().unwrap() else {
                unreachable!()
            };

            assert!(matches!(
                request_id,
                AppRequestId::Sync(SyncRequestId::SingleBlock {
                    id: SingleLookupReqId { req_id, .. },
                }) if *req_id == i
            ));
        }
    }

    #[tokio::test]
    async fn test_peer_disconnected() {
        let fork_context = std::sync::Arc::new(ForkContext::new::<MainnetEthSpec>(
            Slot::new(0),
            Hash256::ZERO,
            &MainnetEthSpec::default_spec(),
        ));
        let mut limiter: SelfRateLimiter<AppRequestId, MainnetEthSpec> =
            SelfRateLimiter::new(None, fork_context).unwrap();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        for peer in [peer1, peer2] {
            for i in 1..=5u32 {
                let result = limiter.allows(
                    peer,
                    AppRequestId::Sync(SyncRequestId::SingleBlock {
                        id: SingleLookupReqId {
                            lookup_id: i,
                            req_id: i,
                        },
                    }),
                    RequestType::Ping(Ping { data: i as u64 }),
                );

                // Check that the limiter allows the first two requests.
                if i <= 2 {
                    assert!(result.is_ok());
                } else {
                    assert!(result.is_err());
                }
            }
        }

        assert!(limiter.active_requests.contains_key(&peer1));
        assert!(
            limiter
                .delayed_requests
                .contains_key(&(peer1, Protocol::Ping))
        );
        assert!(limiter.active_requests.contains_key(&peer2));
        assert!(
            limiter
                .delayed_requests
                .contains_key(&(peer2, Protocol::Ping))
        );

        // Check that the limiter returns the IDs of pending requests and that the IDs are ordered correctly.
        let mut failed_requests = limiter.peer_disconnected(peer1);
        for i in 3..=5u32 {
            let (request_id, _) = failed_requests.remove(0);
            assert!(matches!(
                request_id,
                AppRequestId::Sync(SyncRequestId::SingleBlock {
                        id: SingleLookupReqId { req_id, .. },
                }) if req_id == i
            ));
        }

        // Check that peer1’s active and delayed requests have been removed.
        assert!(!limiter.active_requests.contains_key(&peer1));
        assert!(
            !limiter
                .delayed_requests
                .contains_key(&(peer1, Protocol::Ping))
        );

        assert!(limiter.active_requests.contains_key(&peer2));
        assert!(
            limiter
                .delayed_requests
                .contains_key(&(peer2, Protocol::Ping))
        );
    }
}
