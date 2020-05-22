use crate::discovery::Discovery;
use crate::rpc::*;
use delegate::DelegatingHandler;
pub(super) use delegate::{
    DelegateError, DelegateIn, DelegateInProto, DelegateOut, DelegateOutInfo, DelegateOutProto,
};
use libp2p::{
    core::upgrade::{InboundUpgrade, OutboundUpgrade},
    gossipsub::Gossipsub,
    identify::Identify,
    swarm::{
        protocols_handler::{
            KeepAlive, ProtocolsHandlerEvent, ProtocolsHandlerUpgrErr, SubstreamProtocol,
        },
        NegotiatedSubstream, ProtocolsHandler,
    },
};
use std::task::{Context, Poll};
use types::EthSpec;

mod delegate;

/// Handler that combines Lighthouse's Behaviours' handlers in a delegating manner.
pub struct BehaviourHandler<TSpec: EthSpec> {
    /// Handler combining all sub behaviour's handlers.
    delegate: DelegatingHandler<TSpec>,
    /// Keep alive for this handler.
    keep_alive: KeepAlive,
}

impl<TSpec: EthSpec> BehaviourHandler<TSpec> {
    pub fn new(
        gossipsub: &mut Gossipsub,
        rpc: &mut RPC<TSpec>,
        identify: &mut Identify,
        discovery: &mut Discovery<TSpec>,
    ) -> Self {
        BehaviourHandler {
            delegate: DelegatingHandler::new(gossipsub, rpc, identify, discovery),
            keep_alive: KeepAlive::Yes,
        }
    }
}

#[derive(Clone)]
pub enum BehaviourHandlerIn<TSpec: EthSpec> {
    Delegate(DelegateIn<TSpec>),
    // TODO: replace custom with incoming events
    Custom,
}

pub enum BehaviourHandlerOut<TSpec: EthSpec> {
    Delegate(DelegateOut<TSpec>),
    // TODO: replace custom with events to send
    Custom,
}

pub enum BehaviourHandlerError<TSpec: EthSpec> {
    Delegate(DelegateError<TSpec>),
    // TODO: do we need custom errors?
    Custom,
}

impl<TSpec: EthSpec> ProtocolsHandler for BehaviourHandler<TSpec> {
    type InEvent = BehaviourHandlerIn<TSpec>;
    type OutEvent = BehaviourHandlerOut<TSpec>;
    type Error = DelegateError<TSpec>;
    type InboundProtocol = DelegateInProto<TSpec>;
    type OutboundProtocol = DelegateOutProto<TSpec>;
    type OutboundOpenInfo = DelegateOutInfo<TSpec>;

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        self.delegate.listen_protocol()
    }

    fn inject_fully_negotiated_inbound(
        &mut self,
        out: <Self::InboundProtocol as InboundUpgrade<NegotiatedSubstream>>::Output,
    ) {
        self.delegate.inject_fully_negotiated_inbound(out)
    }

    fn inject_fully_negotiated_outbound(
        &mut self,
        out: <Self::OutboundProtocol as OutboundUpgrade<NegotiatedSubstream>>::Output,
        info: Self::OutboundOpenInfo,
    ) {
        self.delegate.inject_fully_negotiated_outbound(out, info)
    }

    fn inject_event(&mut self, event: Self::InEvent) {
        match event {
            BehaviourHandlerIn::Delegate(delegated_ev) => self.delegate.inject_event(delegated_ev),
            BehaviourHandlerIn::Custom => {
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
        self.delegate.inject_dial_upgrade_error(info, err)
    }

    fn connection_keep_alive(&self) -> KeepAlive {
        // TODO: use access to the handlers to define this better
        todo!()
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
        todo!()
    }
}
