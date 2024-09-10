use crate::discovery::Discovery;
use crate::peer_manager::PeerManager;
use crate::rpc::RPC;
use crate::types::SnappyTransform;

use libp2p::identify;
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::NetworkBehaviour;
use libp2p::upnp::tokio::Behaviour as Upnp;
use types::EthSpec;

use super::api_types::RequestId;

pub type SubscriptionFilter =
    gossipsub::MaxCountSubscriptionFilter<gossipsub::WhitelistSubscriptionFilter>;
pub type Gossipsub = gossipsub::Behaviour<SnappyTransform, SubscriptionFilter>;

#[derive(NetworkBehaviour)]
pub(crate) struct Behaviour<E>
where
    E: EthSpec,
{
    /// Keep track of active and pending connections to enforce hard limits.
    pub connection_limits: libp2p::connection_limits::Behaviour,
    /// The peer manager that keeps track of peer's reputation and status.
    pub peer_manager: PeerManager<E>,
    /// The Eth2 RPC specified in the wire-0 protocol.
    pub eth2_rpc: RPC<RequestId, E>,
    /// Discv5 Discovery protocol.
    pub discovery: Discovery<E>,
    /// Keep regular connection to peers and disconnect if absent.
    // NOTE: The id protocol is used for initial interop. This will be removed by mainnet.
    /// Provides IP addresses and peer information.
    pub identify: identify::Behaviour,
    /// Libp2p UPnP port mapping.
    pub upnp: Toggle<Upnp>,
    /// The routing pub-sub mechanism for eth2.
    pub gossipsub: Gossipsub,
}
