use crate::discovery::Discovery;
use crate::rpc::*;
use libp2p::{
    core::upgrade::{InboundUpgrade, OutboundUpgrade},
    gossipsub::Gossipsub,
    identify::Identify,
    swarm::{
        protocols_handler::{
            KeepAlive, ProtocolsHandlerEvent, ProtocolsHandlerSelect, /* TODO: remove */
            ProtocolsHandlerUpgrErr, SubstreamProtocol,
        },
        NegotiatedSubstream, NetworkBehaviour, ProtocolsHandler,
    },
};
use std::task::{Context, Poll};
use types::EthSpec;

/* Auxiliary types for simplicity */
type GossipHandler = <Gossipsub as NetworkBehaviour>::ProtocolsHandler;
type RPCHandler<TSpec> = <RPC<TSpec> as NetworkBehaviour>::ProtocolsHandler;
type IdentifyHandler = <Identify as NetworkBehaviour>::ProtocolsHandler;
type DiscoveryHandler<TSpec> = <Discovery<TSpec> as NetworkBehaviour>::ProtocolsHandler;

/// Inner handler's type.
// TODO: remove this
type SelectHandler<TSpec> = ProtocolsHandlerSelect<
    ProtocolsHandlerSelect<
        ProtocolsHandlerSelect<
            <Gossipsub as NetworkBehaviour>::ProtocolsHandler,
            <RPC<TSpec> as NetworkBehaviour>::ProtocolsHandler,
        >,
        <Identify as NetworkBehaviour>::ProtocolsHandler,
    >,
    <Discovery<TSpec> as NetworkBehaviour>::ProtocolsHandler,
>;

/// `ProtocolsHandler` for `Behaviour`. Currently implemented as a wrapper around the handler
pub struct BehaviourHandler<TSpec: EthSpec> {
    /// Handler for the Gossipsub protocol.
    gossip_handler: GossipHandler,
    /// Handler for the RPC protocol.
    rpc_handler: RPCHandler<TSpec>,
    /// Handler for the Identify protocol.
    identify_handler: IdentifyHandler,
    /// Handler for the Discovery protocol.
    discovery_handler: DiscoveryHandler<TSpec>,
    /// KeepAlive for this handler.
    keep_alive: KeepAlive,
    /// temporary inner select
    // TODO: wipe out this
    inner_select: SelectHandler<TSpec>,
}

impl<TSpec: EthSpec> BehaviourHandler<TSpec> {
    pub fn new(
        gossipsub: &mut Gossipsub,
        rpc: &mut RPC<TSpec>,
        identify: &mut Identify,
        discovery: &mut Discovery<TSpec>,
    ) -> Self {
        // get the handlers
        let gossip_handler = gossipsub.new_handler();
        let rpc_handler = rpc.new_handler();
        let identify_handler = identify.new_handler();
        let discovery_handler = discovery.new_handler();

        // TODO: remove this ASAP
        // combine the handlers
        let inner_select = ProtocolsHandler::select(
            ProtocolsHandler::select(
                ProtocolsHandler::select(gossipsub.new_handler(), rpc.new_handler()),
                identify.new_handler(),
            ),
            discovery.new_handler(),
        );

        BehaviourHandler {
            gossip_handler,
            rpc_handler,
            identify_handler,
            discovery_handler,
            keep_alive: KeepAlive::Yes,
            inner_select,
        }
    }
}

#[derive(Clone)]
pub enum BHInEvent<TSpec: EthSpec> {
    Delegate(DelegateIn<TSpec>),
    Custom,
}

/// Wrapper around the `ProtocolsHandler::InEvent` types of the behaviours.
/// An incoming event of this type is simply delegated to the corresponding behaviour's handler.
#[derive(Debug, Clone)]
pub enum DelegateIn<TSpec: EthSpec> {
    Gossipsub(<GossipHandler as ProtocolsHandler>::InEvent),
    RPC(<RPCHandler<TSpec> as ProtocolsHandler>::InEvent),
    Identify(<IdentifyHandler as ProtocolsHandler>::InEvent),
    Discovery(<DiscoveryHandler<TSpec> as ProtocolsHandler>::InEvent),
}

// NOTE: the current implementation simply delegates all methods to the inner handler.
impl<TSpec: EthSpec> ProtocolsHandler for BehaviourHandler<TSpec> {
    type InEvent = BHInEvent<TSpec>;
    type OutEvent = <SelectHandler<TSpec> as ProtocolsHandler>::OutEvent;
    type Error = <SelectHandler<TSpec> as ProtocolsHandler>::Error;
    type InboundProtocol = <SelectHandler<TSpec> as ProtocolsHandler>::InboundProtocol;
    type OutboundProtocol = <SelectHandler<TSpec> as ProtocolsHandler>::OutboundProtocol;
    type OutboundOpenInfo = <SelectHandler<TSpec> as ProtocolsHandler>::OutboundOpenInfo;

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        self.inner_select.listen_protocol()
    }

    fn inject_fully_negotiated_inbound(
        &mut self,
        out: <Self::InboundProtocol as InboundUpgrade<NegotiatedSubstream>>::Output,
    ) {
        self.inner_select.inject_fully_negotiated_inbound(out)
    }

    fn inject_fully_negotiated_outbound(
        &mut self,
        out: <Self::OutboundProtocol as OutboundUpgrade<NegotiatedSubstream>>::Output,
        info: Self::OutboundOpenInfo,
    ) {
        self.inner_select
            .inject_fully_negotiated_outbound(out, info)
    }

    fn inject_event(&mut self, event: Self::InEvent) {
        match event {
            BHInEvent::Delegate(ev) => match ev {
                // TODO: reduce noice with macros
                DelegateIn::Gossipsub(ev) => self.gossip_handler.inject_event(ev),
                DelegateIn::RPC(ev) => self.rpc_handler.inject_event(ev),
                DelegateIn::Identify(ev) => self.identify_handler.inject_event(ev),
                DelegateIn::Discovery(ev) => self.discovery_handler.inject_event(ev),
            },
            BHInEvent::Custom => {
                // TODO: implement
            }
        }
    }

    fn inject_dial_upgrade_error(
        &mut self,
        info: Self::OutboundOpenInfo,
        err: ProtocolsHandlerUpgrErr<
            <Self::OutboundProtocol as OutboundUpgrade<NegotiatedSubstream>>::Error,
        >,
    ) {
        self.inner_select.inject_dial_upgrade_error(info, err)
    }

    fn connection_keep_alive(&self) -> KeepAlive {
        // TODO: add better handling of the keep alive
        self.inner_select.connection_keep_alive()
    }

    fn poll(
        &mut self,
        cx: &mut Context,
    ) -> Poll<
        ProtocolsHandlerEvent<
            Self::OutboundProtocol,
            Self::OutboundOpenInfo,
            Self::OutEvent,
            Self::Error,
        >,
    > {
        self.inner_select.poll(cx)
    }
}
