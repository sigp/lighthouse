//! Collection of Peer-specific types and data structures. The peerdb has exclusive access
//! to some attributes of peer structures to ensure mutability of peer variables occur only
//! through the PeerDb.

pub mod client;
pub mod peer_info;
pub mod score;
pub mod sync_status;
