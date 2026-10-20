use crate::PeerId;
use crate::rpc::config::InboundRateLimiterConfig;
use crate::rpc::handler::RESP_TIMEOUT;
use crate::rpc::rate_limiter::{RPCRateLimiter, RateLimitedErr, RateLimiterItem};
use crate::rpc::{InboundRequestId, MAX_CONCURRENT_REQUESTS, Protocol, RequestType};
use futures::FutureExt;
use libp2p::swarm::ConnectionId;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio_util::time::DelayQueue;
use tracing::debug;
use types::{EthSpec, ForkContext};

/// The maximum time the execution of a request may be delayed to comply with the rate limit
/// quota. Requests that cannot be executed within this deadline are rejected with a rate limited
/// error instead, since the connection handler times out the inbound substream after
/// [`RESP_TIMEOUT`] and the requester will likely have given up on the request by then.
const MAX_REQUEST_DELAY: Duration = RESP_TIMEOUT;

/// A request that was rate limited or waiting on other rate limited requests for the same peer
/// and protocol.
struct DelayedRequest<E: EthSpec> {
    peer_id: PeerId,
    request_id: InboundRequestId,
    request_type: RequestType<E>,
    received_at: Instant,
}

/// An active inbound request received via RPC.
pub(super) struct ActiveInboundRequest<E: EthSpec> {
    pub peer_id: PeerId,
    pub request_type: RequestType<E>,
}

/// The result of checking a new inbound request against the rate limiter.
pub(super) enum Admission<E: EthSpec> {
    /// The request may be executed immediately.
    Execute(RequestType<E>),
    /// The request was queued and will be released once the rate limiter allows its execution.
    Delayed,
    /// The request cannot be executed within [`MAX_REQUEST_DELAY`] and should be answered with a
    /// rate limited error instead.
    Reject(RequestType<E>),
    /// The maximum number of concurrent requests for the peer and protocol is already reached and
    /// the request should be answered with a rate limited error.
    RejectConcurrent(RequestType<E>),
}

/// A request released from the delayed requests queue.
pub(super) enum ReadyRequest<E: EthSpec> {
    /// The rate limiter now allows the execution of the request.
    Execute {
        peer_id: PeerId,
        request_id: InboundRequestId,
        request_type: RequestType<E>,
    },
    /// The request cannot be executed within [`MAX_REQUEST_DELAY`] of being received and should
    /// be answered with a rate limited error instead.
    Reject { request_id: InboundRequestId },
}

/// Limits the rate of inbound requests by delaying or rejecting them *before* they are executed,
/// so that no memory is consumed by responses that cannot be sent yet. A request is charged for
/// the maximum number of responses it may produce, mirroring how the responses were counted
/// against the quota when they were sent individually.
pub(super) struct InboundRateLimiter<E: EthSpec> {
    /// Rate limiter that determines whether a request may be executed. When `None`, no rate
    /// limiting is applied and requests are executed as soon as they are admitted.
    limiter: Option<RPCRateLimiter>,
    /// Active inbound requests that are awaiting a response.
    active_requests: HashMap<InboundRequestId, ActiveInboundRequest<E>>,
    /// Requests waiting for the rate limiter to allow their execution.
    delayed_requests: HashMap<(PeerId, Protocol), VecDeque<DelayedRequest<E>>>,
    /// The delay until the next request of a peer and protocol may be executed.
    next_request: DelayQueue<(PeerId, Protocol)>,
}

impl<E: EthSpec> InboundRateLimiter<E> {
    /// Creates a new [`InboundRateLimiter`] based on configuration values.
    pub fn new(
        config: Option<InboundRateLimiterConfig>,
        fork_context: Arc<ForkContext>,
    ) -> Result<Self, &'static str> {
        let limiter = if let Some(config) = config {
            Some(RPCRateLimiter::new_with_config(config.0, fork_context)?)
        } else {
            None
        };
        Ok(InboundRateLimiter {
            limiter,
            active_requests: HashMap::new(),
            delayed_requests: HashMap::new(),
            next_request: DelayQueue::new(),
        })
    }

    /// Checks whether the rate limiter allows the request to be executed now. Requests that
    /// cannot be executed now are queued until the rate limiter allows them, or rejected if
    /// their execution cannot start within [`MAX_REQUEST_DELAY`]. Also rejects requests that
    /// exceed the maximum number of concurrent requests per peer and protocol.
    pub fn allows(
        &mut self,
        peer_id: PeerId,
        request_id: InboundRequestId,
        request_type: RequestType<E>,
    ) -> Admission<E> {
        // Goodbye requests expect no response and must be processed immediately, so that the
        // disconnection is handled promptly.
        if matches!(request_type.protocol(), Protocol::Goodbye) {
            return Admission::Execute(request_type);
        }

        // Enforce the maximum number of concurrent requests per peer and protocol, counting
        // requests that have not yet been completed (including delayed ones).
        let active_request_count = self
            .active_requests
            .values()
            .filter(|request| {
                request.peer_id == peer_id
                    && request.request_type.protocol() == request_type.protocol()
            })
            .count();
        if active_request_count >= MAX_CONCURRENT_REQUESTS {
            debug!(%peer_id, protocol = %request_type.protocol(), "Rejecting request that exceeds the concurrent request limit");
            metrics::inc_counter(&crate::metrics::INBOUND_LIMITER_REJECTED_REQUESTS);
            return Admission::RejectConcurrent(request_type);
        }

        // Track the request as active before it is executed or queued, so that the concurrent
        // request limit above accounts for it.
        let active_request = ActiveInboundRequest {
            peer_id,
            request_type: request_type.clone(),
        };

        let Some(limiter) = self.limiter.as_mut() else {
            self.active_requests.insert(request_id, active_request);
            return Admission::Execute(request_type);
        };

        let key = (peer_id, request_type.protocol());
        // If there are already other requests queued for this peer and protocol, this request
        // must be queued behind them to execute the requests in the order they were received.
        // Whether the request can be executed in time is checked once it reaches the front of
        // the queue.
        if let Some(queue) = self.delayed_requests.get_mut(&key) {
            debug!(%peer_id, protocol = %request_type.protocol(), "Delaying request since there are already other requests waiting for execution");
            self.active_requests.insert(request_id, active_request);
            queue.push_back(DelayedRequest {
                peer_id,
                request_id,
                request_type,
                received_at: Instant::now(),
            });
            self.update_delayed_requests_metric();
            return Admission::Delayed;
        }

        match limiter.allows(&peer_id, &request_type) {
            Ok(()) => {
                self.active_requests.insert(request_id, active_request);
                Admission::Execute(request_type)
            }
            Err(RateLimitedErr::TooLarge) => {
                // The request requires more responses than the quota allows in a whole
                // replenishment window, so its execution can never be allowed.
                debug!(%peer_id, protocol = %request_type.protocol(), "Rejecting request that exceeds a whole rate limit quota window");
                metrics::inc_counter(&crate::metrics::INBOUND_LIMITER_REJECTED_REQUESTS);
                Admission::Reject(request_type)
            }
            Err(RateLimitedErr::TooSoon(wait_time)) => {
                if wait_time >= MAX_REQUEST_DELAY {
                    debug!(%peer_id, protocol = %request_type.protocol(), wait_time_ms = wait_time.as_millis(), "Rejecting request that cannot be executed in time");
                    metrics::inc_counter(&crate::metrics::INBOUND_LIMITER_REJECTED_REQUESTS);
                    return Admission::Reject(request_type);
                }
                debug!(%peer_id, protocol = %request_type.protocol(), wait_time_ms = wait_time.as_millis(), "Delaying request execution");
                self.active_requests.insert(request_id, active_request);
                self.next_request.insert(key, wait_time);
                self.delayed_requests
                    .entry(key)
                    .or_default()
                    .push_back(DelayedRequest {
                        peer_id,
                        request_id,
                        request_type,
                        received_at: Instant::now(),
                    });
                self.update_delayed_requests_metric();
                Admission::Delayed
            }
        }
    }

    /// Removes a completed request from the active requests and returns it, so that the caller
    /// can answer it. Returns `None` if the request is no longer tracked as active.
    pub fn complete_request(
        &mut self,
        request_id: InboundRequestId,
    ) -> Option<ActiveInboundRequest<E>> {
        self.active_requests.remove(&request_id)
    }

    /// Re-tracks a request as active after it was completed via [`Self::complete_request`], for
    /// protocols that require the stream to be terminated before the request is fully answered.
    pub fn reinsert_active(
        &mut self,
        request_id: InboundRequestId,
        request: ActiveInboundRequest<E>,
    ) {
        self.active_requests.insert(request_id, request);
    }

    /// Stops tracking a request that ended in the connection handler. The request may still be in
    /// the delayed queue if its substream ended before it was released for execution.
    pub fn request_ended(&mut self, request_id: InboundRequestId) {
        if self.active_requests.remove(&request_id).is_none() {
            return;
        }
        self.delayed_requests.retain(|_key, queue| {
            queue.retain(|request| request.request_id != request_id);
            !queue.is_empty()
        });
        self.update_delayed_requests_metric();
    }

    /// Informs the limiter that a connection has closed. Queued requests received on the
    /// connection and active requests for the connection are dropped.
    pub fn connection_closed(&mut self, peer_id: PeerId, connection_id: ConnectionId) {
        // NOTE: Currently cannot remove entries from the DelayQueue, we will just let them expire
        // and ignore them.
        self.delayed_requests
            .retain(|(map_peer_id, _protocol), queue| {
                if map_peer_id == &peer_id {
                    queue.retain(|request| request.request_id.connection_id != connection_id);
                }
                !queue.is_empty()
            });
        self.active_requests
            .retain(|request_id, _request| request_id.connection_id != connection_id);
        self.update_delayed_requests_metric();
    }

    #[cfg(test)]
    pub(super) fn active_request_count(&self) -> usize {
        self.active_requests.len()
    }

    /// When the next request of a peer and protocol is allowed to be executed, this function
    /// checks the queued requests and releases as many as the rate limiter allows.
    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Vec<ReadyRequest<E>>> {
        // Requests are only queued when a rate limiter is configured, so when there is no limiter
        // there is nothing to release.
        let Some(limiter) = self.limiter.as_mut() else {
            return Poll::Pending;
        };

        let mut ready_requests = vec![];
        while let Poll::Ready(Some(expired)) = self.next_request.poll_expired(cx) {
            let key = expired.into_inner();

            let Entry::Occupied(mut entry) = self.delayed_requests.entry(key) else {
                continue;
            };

            let queue = entry.get_mut();
            // Take delayed requests from the queue, as long as the limiter allows it.
            while let Some(request) = queue.pop_front() {
                let waited = request.received_at.elapsed();
                if waited >= MAX_REQUEST_DELAY {
                    debug!(peer_id = %request.peer_id, protocol = %key.1, waited_ms = waited.as_millis(), "Rejecting queued request whose execution deadline elapsed");
                    metrics::inc_counter(&crate::metrics::INBOUND_LIMITER_REJECTED_REQUESTS);
                    ready_requests.push(ReadyRequest::Reject {
                        request_id: request.request_id,
                    });
                    continue;
                }

                match limiter.allows(&request.peer_id, &request.request_type) {
                    Ok(()) => {
                        metrics::observe_duration(&crate::metrics::INBOUND_REQUEST_IDLING, waited);
                        ready_requests.push(ReadyRequest::Execute {
                            peer_id: request.peer_id,
                            request_id: request.request_id,
                            request_type: request.request_type,
                        });
                    }
                    Err(RateLimitedErr::TooLarge) => {
                        debug!(peer_id = %request.peer_id, protocol = %key.1, "Rejecting queued request that exceeds a whole rate limit quota window");
                        metrics::inc_counter(&crate::metrics::INBOUND_LIMITER_REJECTED_REQUESTS);
                        ready_requests.push(ReadyRequest::Reject {
                            request_id: request.request_id,
                        });
                    }
                    Err(RateLimitedErr::TooSoon(wait_time)) => {
                        if waited.saturating_add(wait_time) >= MAX_REQUEST_DELAY {
                            // The requester will have timed out by the time the request may
                            // be executed, so executing it would be wasted work.
                            debug!(peer_id = %request.peer_id, protocol = %key.1, waited_ms = waited.as_millis(), "Rejecting queued request that cannot be executed in time");
                            metrics::inc_counter(
                                &crate::metrics::INBOUND_LIMITER_REJECTED_REQUESTS,
                            );
                            ready_requests.push(ReadyRequest::Reject {
                                request_id: request.request_id,
                            });
                            continue;
                        }
                        // The request was taken from the queue, but the limiter didn't allow it.
                        queue.push_front(request);
                        self.next_request.insert(key, wait_time);
                        break;
                    }
                }
            }
            if queue.is_empty() {
                entry.remove();
            }
        }

        // Prune the rate limiter.
        let _ = limiter.poll_unpin(cx);

        if !ready_requests.is_empty() {
            self.update_delayed_requests_metric();
            return Poll::Ready(ready_requests);
        }
        Poll::Pending
    }

    fn update_delayed_requests_metric(&self) {
        metrics::set_gauge(
            &crate::metrics::INBOUND_LIMITER_DELAYED_REQUESTS,
            self.delayed_requests
                .values()
                .map(VecDeque::len)
                .sum::<usize>() as i64,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::GoodbyeReason;
    use crate::rpc::config::RateLimiterConfig;
    use crate::rpc::methods::{OldBlocksByRangeRequest, StatusMessage, StatusMessageV1};
    use crate::rpc::rate_limiter::Quota;
    use logging::create_test_tracing_subscriber;
    use std::num::NonZeroU64;
    use types::{Epoch, Hash256, MainnetEthSpec, Slot};

    fn limiter(config: RateLimiterConfig) -> InboundRateLimiter<MainnetEthSpec> {
        limiter_with_optional_config(Some(config))
    }

    fn limiter_with_optional_config(
        config: Option<RateLimiterConfig>,
    ) -> InboundRateLimiter<MainnetEthSpec> {
        create_test_tracing_subscriber();
        let fork_context = Arc::new(ForkContext::new::<MainnetEthSpec>(
            Slot::new(0),
            Hash256::ZERO,
            &MainnetEthSpec::default_spec(),
        ));
        InboundRateLimiter::new(config.map(InboundRateLimiterConfig), fork_context).unwrap()
    }

    fn request_id(id: usize) -> InboundRequestId {
        InboundRequestId::new_unchecked(0, id)
    }

    fn status_request() -> RequestType<MainnetEthSpec> {
        RequestType::Status(StatusMessage::V1(StatusMessageV1 {
            fork_digest: [0; 4],
            finalized_root: Hash256::ZERO,
            finalized_epoch: Epoch::new(0),
            head_root: Hash256::ZERO,
            head_slot: Slot::new(0),
        }))
    }

    /// Test that rate limited requests are delayed and released once the quota replenishes.
    #[tokio::test]
    async fn test_rate_limited_request_delayed() {
        let mut limiter = limiter(RateLimiterConfig {
            status_quota: Quota::n_every_millis(NonZeroU64::new(1).unwrap(), 100),
            ..Default::default()
        });
        let peer_id = PeerId::random();

        // The first request is allowed immediately, the second is delayed until the quota
        // replenishes.
        assert!(matches!(
            limiter.allows(peer_id, request_id(0), status_request()),
            Admission::Execute(_)
        ));
        assert!(matches!(
            limiter.allows(peer_id, request_id(1), status_request()),
            Admission::Delayed
        ));
        assert!(limiter.complete_request(request_id(0)).is_some());
        // A third request is queued behind the delayed one.
        assert!(matches!(
            limiter.allows(peer_id, request_id(2), status_request()),
            Admission::Delayed
        ));
        assert_eq!(
            2,
            limiter
                .delayed_requests
                .get(&(peer_id, Protocol::Status))
                .unwrap()
                .len()
        );

        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        assert!(limiter.poll_ready(&mut cx).is_pending());

        // Once the quota replenishes, the next request is released.
        tokio::time::sleep(Duration::from_millis(150)).await;
        let Poll::Ready(ready_requests) = limiter.poll_ready(&mut cx) else {
            panic!("Expected a released request");
        };
        assert!(matches!(
            &ready_requests[..],
            [ReadyRequest::Execute {
                request_id: released_id,
                ..
            }] if *released_id == request_id(1)
        ));
    }

    /// Test that a delayed request is rejected if its execution deadline has elapsed, even when
    /// its rate limit quota has replenished.
    #[tokio::test]
    async fn test_expired_request_rejected_after_quota_replenishes() {
        let mut limiter = limiter(RateLimiterConfig {
            status_quota: Quota::n_every_millis(NonZeroU64::new(1).unwrap(), 100),
            ..Default::default()
        });
        let peer_id = PeerId::random();

        assert!(matches!(
            limiter.allows(peer_id, request_id(0), status_request()),
            Admission::Execute(_)
        ));
        assert!(matches!(
            limiter.allows(peer_id, request_id(1), status_request()),
            Admission::Delayed
        ));

        limiter
            .delayed_requests
            .get_mut(&(peer_id, Protocol::Status))
            .and_then(|queue| queue.front_mut())
            .expect("the delayed request exists")
            .received_at = Instant::now()
            .checked_sub(MAX_REQUEST_DELAY.saturating_add(Duration::from_millis(1)))
            .expect("the monotonic clock has advanced beyond the request delay");

        tokio::time::sleep(Duration::from_millis(150)).await;
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        let Poll::Ready(ready_requests) = limiter.poll_ready(&mut cx) else {
            panic!("Expected the expired request to be rejected");
        };
        assert!(matches!(
            &ready_requests[..],
            [ReadyRequest::Reject { request_id: rejected_id }] if *rejected_id == request_id(1)
        ));
    }

    /// Test that requests whose execution cannot start within [`MAX_REQUEST_DELAY`] are
    /// rejected.
    #[tokio::test]
    async fn test_request_rejected_when_wait_too_long() {
        let mut limiter = limiter(RateLimiterConfig {
            status_quota: Quota::n_every(NonZeroU64::new(1).unwrap(), 60),
            ..Default::default()
        });
        let peer_id = PeerId::random();

        assert!(matches!(
            limiter.allows(peer_id, request_id(0), status_request()),
            Admission::Execute(_)
        ));
        // The second request would have to wait ~60s, far beyond the requester's patience.
        assert!(matches!(
            limiter.allows(peer_id, request_id(1), status_request()),
            Admission::Reject(_)
        ));
        assert!(limiter.delayed_requests.is_empty());
    }

    /// Test that requests requiring more responses than a whole quota window allows are
    /// rejected.
    #[tokio::test]
    async fn test_request_rejected_when_too_large() {
        let mut limiter = limiter(RateLimiterConfig {
            blocks_by_range_quota: Quota::n_every(NonZeroU64::new(1).unwrap(), 10),
            ..Default::default()
        });
        let peer_id = PeerId::random();

        // A request for 10 blocks costs 10 tokens, which exceeds the quota of 1 token.
        assert!(matches!(
            limiter.allows(
                peer_id,
                request_id(0),
                RequestType::BlocksByRange(OldBlocksByRangeRequest::new(0, 10, 1)),
            ),
            Admission::Reject(_)
        ));
    }

    /// Test that the concurrent request limit bounds active requests regardless of whether rate
    /// limiting is enabled.
    #[tokio::test]
    async fn test_concurrent_request_limit() {
        let configurations = [
            (
                Some(RateLimiterConfig {
                    status_quota: Quota::one_every(1),
                    ..Default::default()
                }),
                true,
            ),
            (None, false),
        ];

        for (config, expect_second_request_delayed) in configurations {
            let mut limiter = limiter_with_optional_config(config);
            let peer_id = PeerId::random();

            assert!(matches!(
                limiter.allows(peer_id, request_id(0), status_request()),
                Admission::Execute(_)
            ));

            let second_admission = limiter.allows(peer_id, request_id(1), status_request());
            if expect_second_request_delayed {
                assert!(matches!(second_admission, Admission::Delayed));
            } else {
                assert!(matches!(second_admission, Admission::Execute(_)));
            }

            assert!(matches!(
                limiter.allows(peer_id, request_id(2), status_request()),
                Admission::RejectConcurrent(_)
            ));
            assert_eq!(MAX_CONCURRENT_REQUESTS, limiter.active_request_count());
        }
    }

    /// Test that a request ending in the handler is removed from both active tracking and the
    /// delayed queue.
    #[tokio::test]
    async fn test_request_ended() {
        let mut limiter = limiter(RateLimiterConfig {
            status_quota: Quota::n_every_millis(NonZeroU64::new(1).unwrap(), 100),
            ..Default::default()
        });
        let peer_id = PeerId::random();

        assert!(matches!(
            limiter.allows(peer_id, request_id(0), status_request()),
            Admission::Execute(_)
        ));
        assert!(matches!(
            limiter.allows(peer_id, request_id(1), status_request()),
            Admission::Delayed
        ));

        limiter.request_ended(request_id(1));
        assert_eq!(1, limiter.active_request_count());
        assert!(limiter.delayed_requests.is_empty());

        // The stale delay-queue key must not release the ended request later.
        tokio::time::sleep(Duration::from_millis(150)).await;
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        assert!(limiter.poll_ready(&mut cx).is_pending());
    }

    /// Test that Goodbye requests are always executed immediately.
    #[tokio::test]
    async fn test_goodbye_always_executed() {
        let mut limiter = limiter(RateLimiterConfig {
            goodbye_quota: Quota::one_every(60),
            ..Default::default()
        });
        let peer_id = PeerId::random();

        for i in 0..=MAX_CONCURRENT_REQUESTS {
            assert!(matches!(
                limiter.allows(
                    peer_id,
                    request_id(i),
                    RequestType::Goodbye(GoodbyeReason::ClientShutdown),
                ),
                Admission::Execute(_)
            ));
        }
        assert_eq!(0, limiter.active_request_count());
    }

    /// Test that queued requests of a closed connection are dropped without affecting another
    /// connection to the same peer.
    #[tokio::test]
    async fn test_connection_closed() {
        let mut limiter = limiter(RateLimiterConfig {
            status_quota: Quota::n_every(NonZeroU64::new(1).unwrap(), 1),
            ..Default::default()
        });
        let peer_id = PeerId::random();
        let other_connection_request = InboundRequestId::new_unchecked(1, 0);

        assert!(matches!(
            limiter.allows(peer_id, request_id(0), status_request()),
            Admission::Execute(_)
        ));
        assert!(limiter.complete_request(request_id(0)).is_some());
        assert!(matches!(
            limiter.allows(peer_id, request_id(1), status_request()),
            Admission::Delayed
        ));
        assert!(matches!(
            limiter.allows(peer_id, other_connection_request, status_request()),
            Admission::Delayed
        ));

        limiter.connection_closed(peer_id, ConnectionId::new_unchecked(0));
        assert_eq!(1, limiter.active_request_count());
        assert!(
            limiter
                .active_requests
                .contains_key(&other_connection_request)
        );
        assert_eq!(
            limiter
                .delayed_requests
                .get(&(peer_id, Protocol::Status))
                .and_then(|queue| queue.front())
                .map(|request| request.request_id),
            Some(other_connection_request)
        );
    }
}
