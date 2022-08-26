use crate::discovery::Discovery;
use crate::peer_manager::PeerManager;
use crate::rpc::{ReqId, RPC};
use crate::types::SnappyTransform;

use libp2p::gossipsub::subscription_filter::{
    MaxCountSubscriptionFilter, WhitelistSubscriptionFilter,
};
use libp2p::gossipsub::Gossipsub as BaseGossipsub;
use libp2p::identify::Identify;
use libp2p::swarm::NetworkBehaviour;
use libp2p::NetworkBehaviour;
use types::EthSpec;

use super::api_types::RequestId;

pub type SubscriptionFilter = MaxCountSubscriptionFilter<WhitelistSubscriptionFilter>;
pub type Gossipsub = BaseGossipsub<SnappyTransform, SubscriptionFilter>;

#[derive(NetworkBehaviour)]
pub(crate) struct Behaviour<AppReqId: ReqId, TSpec: EthSpec> {
    /// The routing pub-sub mechanism for eth2.
    pub gossipsub: Gossipsub,
    /// The Eth2 RPC specified in the wire-0 protocol.
    pub eth2_rpc: RPC<RequestId<AppReqId>, TSpec>,
    /// Discv5 Discovery protocol.
    pub discovery: Discovery<TSpec>,
    /// Keep regular connection to peers and disconnect if absent.
    // NOTE: The id protocol is used for initial interop. This will be removed by mainnet.
    /// Provides IP addresses and peer information.
    pub identify: Identify,
    /// The peer manager that keeps track of peer's reputation and status.
    pub peer_manager: PeerManager<TSpec>,
}
