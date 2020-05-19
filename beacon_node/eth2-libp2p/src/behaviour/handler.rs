use crate::discovery::Discovery;
use crate::rpc::*;
use libp2p::{
    core::upgrade::{InboundUpgrade, OutboundUpgrade},
    gossipsub::Gossipsub,
    identify::Identify,
    swarm::{
        protocols_handler::{
            KeepAlive, ProtocolsHandlerEvent, ProtocolsHandlerUpgrErr, SubstreamProtocol,
        },
        NegotiatedSubstream, NetworkBehaviour, ProtocolsHandler, ProtocolsHandlerSelect,
    },
};
use std::task::{Context, Poll};
use types::EthSpec;

/// Inner handler's type.
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
/// produced by combining all the sub-behaviour's handlers using `ProtocolsHandler::select`.
pub struct BehaviourHandler<TSpec: EthSpec> {
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

        // combine the handlers
        let inner_select = ProtocolsHandler::select(
            ProtocolsHandler::select(
                ProtocolsHandler::select(gossip_handler, rpc_handler),
                identify_handler,
            ),
            discovery_handler,
        );

        BehaviourHandler { inner_select }
    }
}

// NOTE: the current implementation simply delegates all methods to the inner handler.
impl<TSpec: EthSpec> ProtocolsHandler for BehaviourHandler<TSpec> {
    type InEvent = <SelectHandler<TSpec> as ProtocolsHandler>::InEvent;
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
        self.inner_select.inject_event(event)
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
