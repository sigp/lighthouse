use crate::error::ApiResult;
use crate::response_builder::ResponseBuilder;
use crate::NetworkService;
use beacon_chain::BeaconChainTypes;
use eth2_libp2p::{Multiaddr, PeerId};
use hyper::{Body, Request};
use std::sync::Arc;

/// HTTP handler to return the list of libp2p multiaddr the client is listening on.
///
/// Returns a list of `Multiaddr`, serialized according to their `serde` impl.
pub fn get_listen_addresses<T: BeaconChainTypes>(req: Request<Body>) -> ApiResult {
    let network = req
        .extensions()
        .get::<Arc<NetworkService<T>>>()
        .expect("The network service should always be there, we put it there");
    let multiaddresses: Vec<Multiaddr> = network.listen_multiaddrs();
    ResponseBuilder::new(&req)?.body_no_ssz(&multiaddresses)
}

/// HTTP handler to return the network port the client is listening on.
///
/// Returns the TCP port number in its plain form (which is also valid JSON serialization)
pub fn get_listen_port<T: BeaconChainTypes>(req: Request<Body>) -> ApiResult {
    let network = req
        .extensions()
        .get::<Arc<NetworkService<T>>>()
        .expect("The network service should always be there, we put it there")
        .clone();
    ResponseBuilder::new(&req)?.body(&network.listen_port())
}

/// HTTP handler to return the Discv5 ENR from the client's libp2p service.
///
/// ENR is encoded as base64 string.
pub fn get_enr<T: BeaconChainTypes>(req: Request<Body>) -> ApiResult {
    let network = req
        .extensions()
        .get::<Arc<NetworkService<T>>>()
        .expect("The network service should always be there, we put it there");
    ResponseBuilder::new(&req)?.body_no_ssz(&network.local_enr().to_base64())
}

/// HTTP handler to return the `PeerId` from the client's libp2p service.
///
/// PeerId is encoded as base58 string.
pub fn get_peer_id<T: BeaconChainTypes>(req: Request<Body>) -> ApiResult {
    let network = req
        .extensions()
        .get::<Arc<NetworkService<T>>>()
        .expect("The network service should always be there, we put it there");
    ResponseBuilder::new(&req)?.body_no_ssz(&network.local_peer_id().to_base58())
}

/// HTTP handler to return the number of peers connected in the client's libp2p service.
pub fn get_peer_count<T: BeaconChainTypes>(req: Request<Body>) -> ApiResult {
    let network = req
        .extensions()
        .get::<Arc<NetworkService<T>>>()
        .expect("The network service should always be there, we put it there");
    ResponseBuilder::new(&req)?.body(&network.connected_peers())
}

/// HTTP handler to return the list of peers connected to the client's libp2p service.
///
/// Peers are presented as a list of `PeerId::to_string()`.
pub fn get_peer_list<T: BeaconChainTypes>(req: Request<Body>) -> ApiResult {
    let network = req
        .extensions()
        .get::<Arc<NetworkService<T>>>()
        .expect("The network service should always be there, we put it there");
    let connected_peers: Vec<String> = network
        .connected_peer_set()
        .iter()
        .map(PeerId::to_string)
        .collect();
    ResponseBuilder::new(&req)?.body_no_ssz(&connected_peers)
}
