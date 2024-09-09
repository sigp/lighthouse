use crate::rpc::{Protocol, SubstreamId};
use libp2p::swarm::ConnectionId;
use libp2p::PeerId;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::time::Duration;

/// Restricts more than two inbound requests from running simultaneously on the same protocol per peer.
pub(super) struct ActiveRequestsLimiter {
    resp_timeout: Duration,
    requests: HashMap<PeerId, Vec<(Protocol, ConnectionId, SubstreamId)>>,
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
                for (p, _cid, _sid) in entry.get_mut().iter_mut() {
                    // Check if there is a request on the same protocol.
                    if p == &protocol {
                        return false;
                    }
                }

                // Request on the same protocol was not found.
                entry
                    .get_mut()
                    .push((protocol, *connection_id, *substream_id));
                true
            }
            Entry::Vacant(entry) => {
                // No active requests for the peer.
                entry.insert(vec![(protocol, *connection_id, *substream_id)]);
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
        if let Some(requests) = self.requests.get_mut(&peer_id) {
            requests.retain(|(_protocol, cid, sid)| cid != connection_id && sid != substream_id);
        }
    }

    /// Removes the requests with the given PeerId.
    pub(super) fn remove_peer(&mut self, peer_id: &PeerId) {
        self.requests.remove(peer_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
