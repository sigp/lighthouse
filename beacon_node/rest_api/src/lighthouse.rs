//! This contains a collection of lighthouse specific HTTP endpoints.

use crate::response_builder::ResponseBuilder;
use crate::ApiResult;
use eth2_libp2p::{NetworkGlobals, PeerInfo};
use hyper::{Body, Request};
use serde::Serialize;
use std::sync::Arc;
use types::EthSpec;

/// The syncing state of the beacon node.
pub fn syncing<T: EthSpec>(
    req: Request<Body>,
    network_globals: Arc<NetworkGlobals<T>>,
) -> ApiResult {
    ResponseBuilder::new(&req)?.body_no_ssz(&network_globals.sync_state())
}

/// Returns all known peers and corresponding information
pub fn peers<T: EthSpec>(req: Request<Body>, network_globals: Arc<NetworkGlobals<T>>) -> ApiResult {
    let peers: Vec<Peer<T>> = network_globals
        .peers
        .read()
        .peers()
        .map(|(peer_id, peer_info)| Peer {
            peer_id: peer_id.to_string(),
            peer_info: peer_info.clone(),
        })
        .collect();
    ResponseBuilder::new(&req)?.body_no_ssz(&peers)
}

/// Returns all known connected peers and their corresponding information
pub fn connected_peers<T: EthSpec>(
    req: Request<Body>,
    network_globals: Arc<NetworkGlobals<T>>,
) -> ApiResult {
    let peers: Vec<Peer<T>> = network_globals
        .peers
        .read()
        .connected_peers()
        .map(|(peer_id, peer_info)| Peer {
            peer_id: peer_id.to_string(),
            peer_info: peer_info.clone(),
        })
        .collect();
    ResponseBuilder::new(&req)?.body_no_ssz(&peers)
}

/// Information returned by `peers` and `connected_peers`.
#[derive(Clone, Debug, Serialize)]
#[serde(bound = "T: EthSpec")]
struct Peer<T: EthSpec> {
    /// The Peer's ID
    peer_id: String,
    /// The PeerInfo associated with the peer.
    peer_info: PeerInfo<T>,
}
