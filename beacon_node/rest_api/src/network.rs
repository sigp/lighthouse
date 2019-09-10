use crate::helpers::*;
use crate::{ApiError, BoxFut, NetworkService};
use beacon_chain::BeaconChainTypes;
use eth2_libp2p::{Enr, Multiaddr, PeerId};
use hyper::{Body, Request};
use std::sync::Arc;

/// HTTP handler to return the list of libp2p multiaddr the client is listening on.
///
/// Returns a list of `Multiaddr`, serialized according to their `serde` impl.
pub fn get_listen_addresses<T: BeaconChainTypes>(req: Request<Body>) -> BoxFut {
    let network = req
        .extensions()
        .get::<Arc<NetworkService<T>>>()
        .expect("The network service should always be there, we put it there");
    let multiaddresses: Vec<Multiaddr> = network.listen_multiaddrs();
    success_response_json(req, &multiaddresses)
}

/// HTTP handler to return the network port the client is listening on.
///
/// Returns the TCP port number in its plain form (which is also valid JSON serialization)
pub fn get_listen_port<T: BeaconChainTypes>(req: Request<Body>) -> BoxFut {
    let network = req
        .extensions()
        .get::<Arc<NetworkService<T>>>()
        .expect("The network service should always be there, we put it there")
        .clone();

    success_response(req, &network.listen_port())
}

/// HTTP handler to return the Discv5 ENR from the client's libp2p service.
///
/// ENR is encoded as base64 string.
pub fn get_enr<T: BeaconChainTypes>(req: Request<Body>) -> BoxFut {
    let network = req
        .extensions()
        .get::<Arc<NetworkService<T>>>()
        .expect("The network service should always be there, we put it there");

    let enr: Enr = network.local_enr();
    success_response_json(req, &enr.to_base64())
}

/// HTTP handler to return the `PeerId` from the client's libp2p service.
///
/// PeerId is encoded as base58 string.
pub fn get_peer_id<T: BeaconChainTypes>(req: Request<Body>) -> BoxFut {
    let network = req
        .extensions()
        .get::<Arc<NetworkService<T>>>()
        .expect("The network service should always be there, we put it there");

    let peer_id: PeerId = network.local_peer_id();

    success_response_json(req, &peer_id.to_base58())
}

/// HTTP handler to return the number of peers connected in the client's libp2p service.
pub fn get_peer_count<T: BeaconChainTypes>(req: Request<Body>) -> BoxFut {
    let network = req
        .extensions()
        .get::<Arc<NetworkService<T>>>()
        .expect("The network service should always be there, we put it there");

    let connected_peers: usize = network.connected_peers();

    success_response(req, &connected_peers)
}

/// HTTP handler to return the list of peers connected to the client's libp2p service.
///
/// Peers are presented as a list of `PeerId::to_string()`.
pub fn get_peer_list<T: BeaconChainTypes>(req: Request<Body>) -> BoxFut {
    let network = req
        .extensions()
        .get::<Arc<NetworkService<T>>>()
        .expect("The network service should always be there, we put it there");

    let connected_peers: Vec<String> = network
        .connected_peer_set()
        .iter()
        .map(PeerId::to_string)
        .collect();

    success_response_json(req, &connected_peers)
}
