use crate::{success_response, ApiError, ApiResult, NetworkService};
use beacon_chain::BeaconChainTypes;
use eth2_libp2p::{Enr, PeerId};
use hyper::{Body, Request};
use std::sync::Arc;

/// HTTP handle to return the Discv5 ENR from the client's libp2p service.
///
/// ENR is encoded as base64 string.
pub fn get_enr<T: BeaconChainTypes + Send + Sync + 'static>(req: Request<Body>) -> ApiResult {
    let network = req
        .extensions()
        .get::<Arc<NetworkService<T>>>()
        .ok_or_else(|| ApiError::ServerError("NetworkService extension missing".to_string()))?;

    let enr: Enr = network.local_enr();

    Ok(success_response(Body::from(
        serde_json::to_string(&enr.to_base64())
            .map_err(|e| ApiError::ServerError(format!("Unable to serialize Enr: {:?}", e)))?,
    )))
}

/// HTTP handle to return the number of peers connected in the client's libp2p service.
pub fn get_peer_count<T: BeaconChainTypes + Send + Sync + 'static>(
    req: Request<Body>,
) -> ApiResult {
    let network = req
        .extensions()
        .get::<Arc<NetworkService<T>>>()
        .ok_or_else(|| ApiError::ServerError("NetworkService extension missing".to_string()))?;

    let connected_peers: usize = network.connected_peers();

    Ok(success_response(Body::from(
        serde_json::to_string(&connected_peers)
            .map_err(|e| ApiError::ServerError(format!("Unable to serialize Enr: {:?}", e)))?,
    )))
}

/// HTTP handle to return the list of peers connected to the client's libp2p service.
///
/// Peers are presented as a list of `PeerId::to_string()`.
pub fn get_peer_list<T: BeaconChainTypes + Send + Sync + 'static>(req: Request<Body>) -> ApiResult {
    let network = req
        .extensions()
        .get::<Arc<NetworkService<T>>>()
        .ok_or_else(|| ApiError::ServerError("NetworkService extension missing".to_string()))?;

    let connected_peers: Vec<String> = network
        .connected_peer_set()
        .iter()
        .map(PeerId::to_string)
        .collect();

    Ok(success_response(Body::from(
        serde_json::to_string(&connected_peers).map_err(|e| {
            ApiError::ServerError(format!("Unable to serialize Vec<PeerId>: {:?}", e))
        })?,
    )))
}
