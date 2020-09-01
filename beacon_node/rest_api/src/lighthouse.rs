//! This contains a collection of lighthouse specific HTTP endpoints.

use crate::{ApiError, Context};
use beacon_chain::BeaconChainTypes;
use eth2_libp2p::PeerInfo;
use serde::Serialize;
use std::sync::Arc;
use types::EthSpec;

/// Returns all known peers and corresponding information
pub fn peers<T: BeaconChainTypes>(ctx: Arc<Context<T>>) -> Result<Vec<Peer<T::EthSpec>>, ApiError> {
    Ok(ctx
        .network_globals
        .peers
        .read()
        .peers()
        .map(|(peer_id, peer_info)| Peer {
            peer_id: peer_id.to_string(),
            peer_info: peer_info.clone(),
        })
        .collect())
}

/// Returns all known connected peers and their corresponding information
pub fn connected_peers<T: BeaconChainTypes>(
    ctx: Arc<Context<T>>,
) -> Result<Vec<Peer<T::EthSpec>>, ApiError> {
    Ok(ctx
        .network_globals
        .peers
        .read()
        .connected_peers()
        .map(|(peer_id, peer_info)| Peer {
            peer_id: peer_id.to_string(),
            peer_info: peer_info.clone(),
        })
        .collect())
}

/// Information returned by `peers` and `connected_peers`.
#[derive(Clone, Debug, Serialize)]
#[serde(bound = "T: EthSpec")]
pub struct Peer<T: EthSpec> {
    /// The Peer's ID
    peer_id: String,
    /// The PeerInfo associated with the peer.
    peer_info: PeerInfo<T>,
}
