use crate::rpc::{Protocol, SubstreamId};
use libp2p::swarm::ConnectionId;
use libp2p::PeerId;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::Instant;

/// Restricts more than two requests from running simultaneously on the same protocol per peer.
pub(super) struct ActiveRequestsLimiter {
    resp_timeout: Duration,
    requests: HashMap<PeerId, Vec<(Protocol, ConnectionId, SubstreamId, Instant)>>,
}

impl ActiveRequestsLimiter {
    pub(super) fn new(resp_timeout: Duration) -> Self {
        Self {
            resp_timeout,
            requests: HashMap::new(),
        }
    }

    /// Allows if there is not a request on the same protocol.
    pub(super) fn allows(
        &mut self,
        peer_id: PeerId,
        protocol: Protocol,
        connection_id: &ConnectionId,
        substream_id: &SubstreamId,
    ) -> bool {
        match self.requests.entry(peer_id) {
            Entry::Occupied(mut entry) => {
                for (p, cid, sid, requested_at) in entry.get_mut().iter_mut() {
                    // Check if there is a request on the same protocol.
                    if p == &protocol {
                        return if requested_at.elapsed() > self.resp_timeout {
                            // There is an active request on the same protocol, but it has reached the response timeout.
                            // So, the given request is allowed, and the active request is updated.
                            // This helps us avoid leaving a request in the HashMap and ensures that new requests are allowed.
                            *cid = *connection_id;
                            *sid = *substream_id;
                            *requested_at = Instant::now();
                            true
                        } else {
                            false
                        };
                    }
                }

                // Request on the same protocol was not found.
                entry
                    .get_mut()
                    .push((protocol, *connection_id, *substream_id, Instant::now()));
                true
            }
            Entry::Vacant(entry) => {
                // No active requests for the peer.
                entry.insert(vec![(
                    protocol,
                    *connection_id,
                    *substream_id,
                    Instant::now(),
                )]);
                true
            }
        }
    }

    /// Removes the request with the given SubstreamId.
    pub(super) fn remove_request(
        &mut self,
        peer_id: PeerId,
        connection_id: &ConnectionId,
        substream_id: &SubstreamId,
    ) {
        self.requests.get_mut(&peer_id).map(|requests| {
            requests.retain(|(_protocol, cid, sid, _requested_at)| {
                cid != connection_id && sid != substream_id
            });
        });
    }

    /// Removes the requests with the given PeerId.
    pub(super) fn remove_peer(&mut self, peer_id: &PeerId) {
        self.requests.remove(peer_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_limiter() {
        let mut limiter = ActiveRequestsLimiter::new(Duration::from_secs(10));
        let peer_id = PeerId::random();
        let connection_id = ConnectionId::new_unchecked(1);
        let substream_id = SubstreamId::new(1);

        assert!(limiter.allows(peer_id, Protocol::Status, &connection_id, &substream_id));
        // Not allowed since a request for the same protocol is in progress.
        assert!(!limiter.allows(peer_id, Protocol::Status, &connection_id, &substream_id));
        // Allowed since there is no BlocksByRange request in the active requests.
        assert!(limiter.allows(
            peer_id,
            Protocol::BlocksByRange,
            &connection_id,
            &SubstreamId::new(2)
        ));
        // Allowed since there is no request from the peer in the active requests.
        assert!(limiter.allows(
            PeerId::random(),
            Protocol::Status,
            &connection_id,
            &substream_id
        ));

        // Remove the Status request.
        limiter.remove_request(peer_id, &connection_id, &substream_id);
        assert!(limiter.allows(
            peer_id,
            Protocol::Status,
            &connection_id,
            &SubstreamId::new(3)
        ));

        // Remove the peer.
        limiter.remove_peer(&peer_id);
        assert!(limiter.allows(
            peer_id,
            Protocol::Status,
            &connection_id,
            &SubstreamId::new(4)
        ));
        assert!(limiter.allows(
            peer_id,
            Protocol::BlocksByRange,
            &connection_id,
            &SubstreamId::new(5)
        ));
    }

    // Test that a request for the same protocol is allowed if a preceding request has reached the
    // response timeout.
    #[test]
    fn test_timeout() {
        let resp_timeout = Duration::from_secs(2);
        let peer_id = PeerId::random();
        let connection_id = ConnectionId::new_unchecked(1);
        let mut limiter = ActiveRequestsLimiter::new(resp_timeout);

        // Allows the first request.
        assert!(limiter.allows(
            peer_id,
            Protocol::Status,
            &connection_id,
            &SubstreamId::new(1)
        ));
        let requested_at1 = limiter.requests.get(&peer_id).unwrap().first().unwrap().3;
        sleep(resp_timeout);
        // The second request is allowed since the first request has been reached resp_timeout.
        assert!(limiter.allows(
            peer_id,
            Protocol::Status,
            &connection_id,
            &SubstreamId::new(2)
        ));

        // Check that the active request has been updated with the second request.
        let (protocol, cid, sid, requested_at2) =
            limiter.requests.get(&peer_id).unwrap().first().unwrap();
        assert!(matches!(protocol, Protocol::Status));
        assert_eq!(cid, &connection_id);
        assert_eq!(sid, &SubstreamId::new(2));
        assert!(requested_at1.lt(requested_at2));
    }
}
