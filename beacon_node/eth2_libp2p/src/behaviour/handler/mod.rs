use crate::rpc::*;
use delegate::DelegatingHandler;
pub(super) use delegate::{
    DelegateError, DelegateIn, DelegateInProto, DelegateOut, DelegateOutInfo, DelegateOutProto,
};
use libp2p::{
    core::upgrade::{InboundUpgrade, OutboundUpgrade},
    gossipsub::Gossipsub,
    identify::Identify,
    swarm::protocols_handler::{
        KeepAlive, ProtocolsHandlerEvent, ProtocolsHandlerUpgrErr, SubstreamProtocol,
    },
    swarm::{NegotiatedSubstream, ProtocolsHandler},
};
use std::task::{Context, Poll};
use types::EthSpec;

mod delegate;

/// Handler that combines Lighthouse's Behaviours' handlers in a delegating manner.
pub struct BehaviourHandler<TSpec: EthSpec> {
    /// Handler combining all sub behaviour's handlers.
    delegate: DelegatingHandler<TSpec>,
    /// Flag indicating if the handler is shutting down.
    shutting_down: bool,
}

impl<TSpec: EthSpec> BehaviourHandler<TSpec> {
    pub fn new(gossipsub: &mut Gossipsub, rpc: &mut RPC<TSpec>, identify: &mut Identify) -> Self {
        BehaviourHandler {
            delegate: DelegatingHandler::new(gossipsub, rpc, identify),
            shutting_down: false,
        }
    }
}

#[derive(Clone)]
pub enum BehaviourHandlerIn<TSpec: EthSpec> {
    Delegate(DelegateIn<TSpec>),
    /// Start the shutdown process.
    Shutdown(Option<(RequestId, RPCRequest<TSpec>)>),
}

pub enum BehaviourHandlerOut<TSpec: EthSpec> {
    Delegate(Box<DelegateOut<TSpec>>),
    // TODO: replace custom with events to send
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
            /* Events comming from the behaviour */
            BehaviourHandlerIn::Shutdown(last_message) => {
                self.shutting_down = true;
                self.delegate.rpc_mut().shutdown(last_message);
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

    // We don't use the keep alive to disconnect. This is handled in the poll
    fn connection_keep_alive(&self) -> KeepAlive {
        KeepAlive::Yes
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
        // Disconnect if the sub-handlers are ready.
        if self.shutting_down {
            let rpc_keep_alive = self.delegate.rpc().connection_keep_alive();
            let identify_keep_alive = self.delegate.identify().connection_keep_alive();
            if KeepAlive::No == rpc_keep_alive.max(identify_keep_alive) {
                return Poll::Ready(ProtocolsHandlerEvent::Close(DelegateError::Disconnected));
            }
        }

        match self.delegate.poll(cx) {
            Poll::Ready(ProtocolsHandlerEvent::Custom(event)) => {
                return Poll::Ready(ProtocolsHandlerEvent::Custom(
                    BehaviourHandlerOut::Delegate(Box::new(event)),
                ))
            }
            Poll::Ready(ProtocolsHandlerEvent::Close(err)) => {
                return Poll::Ready(ProtocolsHandlerEvent::Close(err))
            }
            Poll::Ready(ProtocolsHandlerEvent::OutboundSubstreamRequest { protocol, info }) => {
                return Poll::Ready(ProtocolsHandlerEvent::OutboundSubstreamRequest {
                    protocol,
                    info,
                });
            }
            Poll::Pending => (),
        }

        Poll::Pending
    }
}
