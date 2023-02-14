use std::{
    collections::{hash_map::Entry, HashMap, VecDeque},
    task::{Context, Poll},
    time::Duration,
};

use futures::FutureExt;
use libp2p::{swarm::NotifyHandler, PeerId};
use slog::{crit, debug, Logger};
use smallvec::SmallVec;
use tokio_util::time::DelayQueue;
use types::EthSpec;

use super::{
    config::OutboundRateLimiterConfig,
    rate_limiter::{RPCRateLimiter as RateLimiter, RateLimitedErr},
    BehaviourAction, OutboundRequest, Protocol, RPCSend, ReqId,
};

/// A request that was rate limited or waiting on rate limited requests for the same peer and
/// protocol.
struct QueuedRequest<Id: ReqId, TSpec: EthSpec> {
    req: OutboundRequest<TSpec>,
    request_id: Id,
}

pub(crate) struct SelfRateLimiter<Id: ReqId, TSpec: EthSpec> {
    /// Requests queued for sending per peer. This requests are stored when the self rate
    /// limiter rejects them. Rate limiting is based on a Peer and Protocol basis, therefore
    /// are stored in the same way.
    delayed_requests: HashMap<(PeerId, Protocol), VecDeque<QueuedRequest<Id, TSpec>>>,
    /// The delay required to allow a peer's outbound request per protocol.
    next_peer_request: DelayQueue<(PeerId, Protocol)>,
    /// Rate limiter for our own requests.
    limiter: RateLimiter,
    /// Requests that are ready to be sent.
    ready_requests: SmallVec<[BehaviourAction<Id, TSpec>; 3]>,
    /// Slog logger.
    log: Logger,
}

/// Error returned when the rate limiter does not accept a request.
// NOTE: this is currently not used, but might be useful for debugging.
pub enum Error {
    /// There are queued requests for this same peer and protocol.
    PendingRequests,
    /// Request was tried but rate limited.
    RateLimited,
}

impl<Id: ReqId, TSpec: EthSpec> SelfRateLimiter<Id, TSpec> {
    /// Creates a new [`SelfRateLimiter`] based on configration values.
    pub fn new(config: OutboundRateLimiterConfig, log: Logger) -> Result<Self, &'static str> {
        debug!(log, "Using self rate limiting params"; "config" => ?config);
        // Destructure to make sure every configuration value is used.
        let OutboundRateLimiterConfig {
            ping_quota,
            meta_data_quota,
            status_quota,
            goodbye_quota,
            blocks_by_range_quota,
            blocks_by_root_quota,
        } = config;

        let limiter = RateLimiter::builder()
            .set_quota(Protocol::Ping, ping_quota)
            .set_quota(Protocol::MetaData, meta_data_quota)
            .set_quota(Protocol::Status, status_quota)
            .set_quota(Protocol::Goodbye, goodbye_quota)
            .set_quota(Protocol::BlocksByRange, blocks_by_range_quota)
            .set_quota(Protocol::BlocksByRoot, blocks_by_root_quota)
            // Manually set the LightClientBootstrap quota, since we use the same rate limiter for
            // inbound and outbound requests, and the LightClientBootstrap is an only inbound
            // protocol.
            .one_every(Protocol::LightClientBootstrap, Duration::from_secs(10))
            .build()?;

        Ok(SelfRateLimiter {
            delayed_requests: Default::default(),
            next_peer_request: Default::default(),
            limiter,
            ready_requests: Default::default(),
            log,
        })
    }

    /// Checks if the rate limiter allows the request. If it's allowed, returns the
    /// [`NetworkBehaviourAction`] that should be emitted. When not allowed, the request is delayed
    /// until it can be sent.
    pub fn allows(
        &mut self,
        peer_id: PeerId,
        request_id: Id,
        req: OutboundRequest<TSpec>,
    ) -> Result<BehaviourAction<Id, TSpec>, Error> {
        let protocol = req.protocol();
        // First check that there are not already other requests waiting to be sent.
        if let Some(queued_requests) = self.delayed_requests.get_mut(&(peer_id, protocol)) {
            queued_requests.push_back(QueuedRequest { req, request_id });

            return Err(Error::PendingRequests);
        }
        match Self::try_send_request(&mut self.limiter, peer_id, request_id, req, &self.log) {
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
    /// request, the [`NetworkBehaviourAction`] that should be emitted is returned. If the request
    /// should be delayed, it's returned with the duration to wait.
    fn try_send_request(
        limiter: &mut RateLimiter,
        peer_id: PeerId,
        request_id: Id,
        req: OutboundRequest<TSpec>,
        log: &Logger,
    ) -> Result<BehaviourAction<Id, TSpec>, (QueuedRequest<Id, TSpec>, Duration)> {
        match limiter.allows(&peer_id, &req) {
            Ok(()) => Ok(BehaviourAction::NotifyHandler {
                peer_id,
                handler: NotifyHandler::Any,
                event: RPCSend::Request(request_id, req),
            }),
            Err(e) => {
                let protocol = req.protocol();
                match e {
                    RateLimitedErr::TooLarge => {
                        // this should never happen with default parameters. Let's just send the request.
                        // Log a crit since this is a config issue.
                        crit!(
                           log,
                            "Self rate limiting error for a batch that will never fit. Sending request anyway. Check configuration parameters.";
                            "protocol" => %req.protocol()
                        );
                        Ok(BehaviourAction::NotifyHandler {
                            peer_id,
                            handler: NotifyHandler::Any,
                            event: RPCSend::Request(request_id, req),
                        })
                    }
                    RateLimitedErr::TooSoon(wait_time) => {
                        debug!(log, "Self rate limiting"; "protocol" => %protocol, "wait_time_ms" => wait_time.as_millis(), "peer_id" => %peer_id);
                        Err((QueuedRequest { req, request_id }, wait_time))
                    }
                }
            }
        }
    }

    /// When a peer and protocol are allowed to send a next request, this function checks the
    /// queued requests and attempts marking as ready as many as the limiter allows.
    fn next_peer_request_ready(&mut self, peer_id: PeerId, protocol: Protocol) {
        if let Entry::Occupied(mut entry) = self.delayed_requests.entry((peer_id, protocol)) {
            let queued_requests = entry.get_mut();
            while let Some(QueuedRequest { req, request_id }) = queued_requests.pop_front() {
                match Self::try_send_request(&mut self.limiter, peer_id, request_id, req, &self.log)
                {
                    Err((rate_limited_req, wait_time)) => {
                        let key = (peer_id, protocol);
                        self.next_peer_request.insert(key, wait_time);
                        queued_requests.push_back(rate_limited_req);
                        // If one fails just wait for the next window that allows sending requests.
                        return;
                    }
                    Ok(event) => self.ready_requests.push(event),
                }
            }
            if queued_requests.is_empty() {
                entry.remove();
            }
        }
    }

    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<BehaviourAction<Id, TSpec>> {
        // First check the requests that were self rate limited, since those might add events to
        // the queue. Also do this this before rate limiter prunning to avoid removing and
        // immediately adding rate limiting keys.
        if let Poll::Ready(Some(Ok(expired))) = self.next_peer_request.poll_expired(cx) {
            let (peer_id, protocol) = expired.into_inner();
            self.next_peer_request_ready(peer_id, protocol);
        }
        // Prune the rate limiter.
        let _ = self.limiter.poll_unpin(cx);

        // Finally return any queued events.
        if !self.ready_requests.is_empty() {
            return Poll::Ready(self.ready_requests.remove(0));
        }

        Poll::Pending
    }
}
