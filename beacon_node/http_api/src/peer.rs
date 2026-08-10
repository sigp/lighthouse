use lighthouse_network::PeerInfo;
use serde::Serialize;

/// Information returned by `peers` and `connected_peers`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Peer {
    /// The Peer's ID
    pub peer_id: String,
    /// The PeerInfo associated with the peer.
    pub peer_info: PeerInfo,
}
