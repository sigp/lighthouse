use crate::rpc::*;
use libp2p::{
    core::either::{EitherError, EitherOutput},
    core::upgrade::{EitherUpgrade, InboundUpgrade, OutboundUpgrade, SelectUpgrade, UpgradeError},
    gossipsub::Gossipsub,
    identify::Identify,
    swarm::{
        protocols_handler::{
            KeepAlive, ProtocolsHandlerEvent, ProtocolsHandlerUpgrErr, SubstreamProtocol,
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

/// Handler that combines Lighthouse's Behaviours' handlers in a delegating manner.
pub(super) struct DelegatingHandler<TSpec: EthSpec> {
    /// Handler for the Gossipsub protocol.
    gossip_handler: GossipHandler,
    /// Handler for the RPC protocol.
    rpc_handler: RPCHandler<TSpec>,
    /// Handler for the Identify protocol.
    identify_handler: IdentifyHandler,
}

impl<TSpec: EthSpec> DelegatingHandler<TSpec> {
    pub fn new(gossipsub: &mut Gossipsub, rpc: &mut RPC<TSpec>, identify: &mut Identify) -> Self {
        DelegatingHandler {
            gossip_handler: gossipsub.new_handler(),
            rpc_handler: rpc.new_handler(),
            identify_handler: identify.new_handler(),
        }
    }

    /// Gives mutable access to the rpc handler.
    pub fn rpc_mut(&mut self) -> &mut RPCHandler<TSpec> {
        &mut self.rpc_handler
    }

    /// Gives access to the rpc handler.
    pub fn rpc(&self) -> &RPCHandler<TSpec> {
        &self.rpc_handler
    }

    /// Gives access to identify's handler.
    pub fn _identify(&self) -> &IdentifyHandler {
        &self.identify_handler
    }
}

// TODO: this can all be created with macros

/// Wrapper around the `ProtocolsHandler::InEvent` types of the handlers.
/// Simply delegated to the corresponding behaviour's handler.
#[derive(Debug, Clone)]
pub enum DelegateIn<TSpec: EthSpec> {
    Gossipsub(<GossipHandler as ProtocolsHandler>::InEvent),
    RPC(<RPCHandler<TSpec> as ProtocolsHandler>::InEvent),
    Identify(<IdentifyHandler as ProtocolsHandler>::InEvent),
}

/// Wrapper around the `ProtocolsHandler::OutEvent` types of the handlers.
/// Simply delegated to the corresponding behaviour's handler.
pub enum DelegateOut<TSpec: EthSpec> {
    Gossipsub(<GossipHandler as ProtocolsHandler>::OutEvent),
    RPC(<RPCHandler<TSpec> as ProtocolsHandler>::OutEvent),
    Identify(Box<<IdentifyHandler as ProtocolsHandler>::OutEvent>),
}

/// Wrapper around the `ProtocolsHandler::Error` types of the handlers.
/// Simply delegated to the corresponding behaviour's handler.
#[derive(Debug)]
pub enum DelegateError<TSpec: EthSpec> {
    Gossipsub(<GossipHandler as ProtocolsHandler>::Error),
    RPC(<RPCHandler<TSpec> as ProtocolsHandler>::Error),
    Identify(<IdentifyHandler as ProtocolsHandler>::Error),
    Disconnected,
}

impl<TSpec: EthSpec> std::error::Error for DelegateError<TSpec> {}

impl<TSpec: EthSpec> std::fmt::Display for DelegateError<TSpec> {
    fn fmt(
        &self,
        formater: &mut std::fmt::Formatter<'_>,
    ) -> std::result::Result<(), std::fmt::Error> {
        match self {
            DelegateError::Gossipsub(err) => err.fmt(formater),
            DelegateError::RPC(err) => err.fmt(formater),
            DelegateError::Identify(err) => err.fmt(formater),
            DelegateError::Disconnected => write!(formater, "Disconnected"),
        }
    }
}

pub type DelegateInProto<TSpec> = SelectUpgrade<
    <GossipHandler as ProtocolsHandler>::InboundProtocol,
    SelectUpgrade<
        <RPCHandler<TSpec> as ProtocolsHandler>::InboundProtocol,
        <IdentifyHandler as ProtocolsHandler>::InboundProtocol,
    >,
>;

pub type DelegateOutProto<TSpec> = EitherUpgrade<
    <GossipHandler as ProtocolsHandler>::OutboundProtocol,
    EitherUpgrade<
        <RPCHandler<TSpec> as ProtocolsHandler>::OutboundProtocol,
        <IdentifyHandler as ProtocolsHandler>::OutboundProtocol,
    >,
>;

// TODO: prob make this an enum
pub type DelegateOutInfo<TSpec> = EitherOutput<
    <GossipHandler as ProtocolsHandler>::OutboundOpenInfo,
    EitherOutput<
        <RPCHandler<TSpec> as ProtocolsHandler>::OutboundOpenInfo,
        <IdentifyHandler as ProtocolsHandler>::OutboundOpenInfo,
    >,
>;

impl<TSpec: EthSpec> ProtocolsHandler for DelegatingHandler<TSpec> {
    type InEvent = DelegateIn<TSpec>;
    type OutEvent = DelegateOut<TSpec>;
    type Error = DelegateError<TSpec>;
    type InboundProtocol = DelegateInProto<TSpec>;
    type OutboundProtocol = DelegateOutProto<TSpec>;
    type OutboundOpenInfo = DelegateOutInfo<TSpec>;
    type InboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, ()> {
        let gossip_proto = self.gossip_handler.listen_protocol();
        let rpc_proto = self.rpc_handler.listen_protocol();
        let identify_proto = self.identify_handler.listen_protocol();

        let timeout = *gossip_proto
            .timeout()
            .max(rpc_proto.timeout())
            .max(identify_proto.timeout());

        let select = SelectUpgrade::new(
            gossip_proto.into_upgrade().1,
            SelectUpgrade::new(rpc_proto.into_upgrade().1, identify_proto.into_upgrade().1),
        );

        SubstreamProtocol::new(select, ()).with_timeout(timeout)
    }

    fn inject_fully_negotiated_inbound(
        &mut self,
        out: <Self::InboundProtocol as InboundUpgrade<NegotiatedSubstream>>::Output,
        _info: Self::InboundOpenInfo,
    ) {
        match out {
            // Gossipsub
            EitherOutput::First(out) => {
                self.gossip_handler.inject_fully_negotiated_inbound(out, ())
            }
            // RPC
            EitherOutput::Second(EitherOutput::First(out)) => {
                self.rpc_handler.inject_fully_negotiated_inbound(out, ())
            }
            // Identify
            EitherOutput::Second(EitherOutput::Second(out)) => self
                .identify_handler
                .inject_fully_negotiated_inbound(out, ()),
        }
    }

    fn inject_fully_negotiated_outbound(
        &mut self,
        protocol: <Self::OutboundProtocol as OutboundUpgrade<NegotiatedSubstream>>::Output,
        info: Self::OutboundOpenInfo,
    ) {
        match (protocol, info) {
            // Gossipsub
            (EitherOutput::First(protocol), EitherOutput::First(info)) => self
                .gossip_handler
                .inject_fully_negotiated_outbound(protocol, info),
            // RPC
            (
                EitherOutput::Second(EitherOutput::First(protocol)),
                EitherOutput::Second(EitherOutput::First(info)),
            ) => self
                .rpc_handler
                .inject_fully_negotiated_outbound(protocol, info),
            // Identify
            (
                EitherOutput::Second(EitherOutput::Second(protocol)),
                EitherOutput::Second(EitherOutput::Second(())),
            ) => self
                .identify_handler
                .inject_fully_negotiated_outbound(protocol, ()),
            // Reaching here means we got a protocol and info for different behaviours
            _ => unreachable!("output and protocol don't match"),
        }
    }

    fn inject_event(&mut self, event: Self::InEvent) {
        match event {
            DelegateIn::Gossipsub(ev) => self.gossip_handler.inject_event(ev),
            DelegateIn::RPC(ev) => self.rpc_handler.inject_event(ev),
            DelegateIn::Identify(()) => self.identify_handler.inject_event(()),
        }
    }

    fn inject_dial_upgrade_error(
        &mut self,
        info: Self::OutboundOpenInfo,
        error: ProtocolsHandlerUpgrErr<
            <Self::OutboundProtocol as OutboundUpgrade<NegotiatedSubstream>>::Error,
        >,
    ) {
        // TODO: find how to clean up
        match info {
            // Gossipsub
            EitherOutput::First(info) => match error {
                ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Select(err)) => {
                    self.gossip_handler.inject_dial_upgrade_error(
                        info,
                        ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Select(err)),
                    )
                }
                ProtocolsHandlerUpgrErr::Timer => self
                    .gossip_handler
                    .inject_dial_upgrade_error(info, ProtocolsHandlerUpgrErr::Timer),
                ProtocolsHandlerUpgrErr::Timeout => self
                    .gossip_handler
                    .inject_dial_upgrade_error(info, ProtocolsHandlerUpgrErr::Timeout),
                ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Apply(EitherError::A(err))) => {
                    self.gossip_handler.inject_dial_upgrade_error(
                        info,
                        ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Apply(err)),
                    )
                }
                ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Apply(_)) => {
                    unreachable!("info and error don't match")
                }
            },
            // RPC
            EitherOutput::Second(EitherOutput::First(info)) => match error {
                ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Select(err)) => {
                    self.rpc_handler.inject_dial_upgrade_error(
                        info,
                        ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Select(err)),
                    )
                }
                ProtocolsHandlerUpgrErr::Timer => self
                    .rpc_handler
                    .inject_dial_upgrade_error(info, ProtocolsHandlerUpgrErr::Timer),
                ProtocolsHandlerUpgrErr::Timeout => self
                    .rpc_handler
                    .inject_dial_upgrade_error(info, ProtocolsHandlerUpgrErr::Timeout),
                ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Apply(EitherError::B(
                    EitherError::A(err),
                ))) => self.rpc_handler.inject_dial_upgrade_error(
                    info,
                    ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Apply(err)),
                ),
                ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Apply(_)) => {
                    unreachable!("info and error don't match")
                }
            },
            // Identify
            EitherOutput::Second(EitherOutput::Second(())) => match error {
                ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Select(err)) => {
                    self.identify_handler.inject_dial_upgrade_error(
                        (),
                        ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Select(err)),
                    )
                }
                ProtocolsHandlerUpgrErr::Timer => self
                    .identify_handler
                    .inject_dial_upgrade_error((), ProtocolsHandlerUpgrErr::Timer),
                ProtocolsHandlerUpgrErr::Timeout => self
                    .identify_handler
                    .inject_dial_upgrade_error((), ProtocolsHandlerUpgrErr::Timeout),
                ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Apply(EitherError::B(
                    EitherError::B(err),
                ))) => self.identify_handler.inject_dial_upgrade_error(
                    (),
                    ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Apply(err)),
                ),
                ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Apply(_)) => {
                    unreachable!("info and error don't match")
                }
            },
        }
    }

    fn connection_keep_alive(&self) -> KeepAlive {
        self.gossip_handler
            .connection_keep_alive()
            .max(self.rpc_handler.connection_keep_alive())
            .max(self.identify_handler.connection_keep_alive())
    }

    #[allow(clippy::type_complexity)]
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
        match self.gossip_handler.poll(cx) {
            Poll::Ready(ProtocolsHandlerEvent::Custom(event)) => {
                return Poll::Ready(ProtocolsHandlerEvent::Custom(DelegateOut::Gossipsub(event)));
            }
            Poll::Ready(ProtocolsHandlerEvent::Close(event)) => {
                return Poll::Ready(ProtocolsHandlerEvent::Close(DelegateError::Gossipsub(
                    event,
                )));
            }
            Poll::Ready(ProtocolsHandlerEvent::OutboundSubstreamRequest { protocol }) => {
                return Poll::Ready(ProtocolsHandlerEvent::OutboundSubstreamRequest {
                    protocol: protocol
                        .map_upgrade(EitherUpgrade::A)
                        .map_info(EitherOutput::First),
                });
            }
            Poll::Pending => (),
        };

        match self.rpc_handler.poll(cx) {
            Poll::Ready(ProtocolsHandlerEvent::Custom(event)) => {
                return Poll::Ready(ProtocolsHandlerEvent::Custom(DelegateOut::RPC(event)));
            }
            Poll::Ready(ProtocolsHandlerEvent::Close(event)) => {
                return Poll::Ready(ProtocolsHandlerEvent::Close(DelegateError::RPC(event)));
            }
            Poll::Ready(ProtocolsHandlerEvent::OutboundSubstreamRequest { protocol }) => {
                return Poll::Ready(ProtocolsHandlerEvent::OutboundSubstreamRequest {
                    protocol: protocol
                        .map_upgrade(|u| EitherUpgrade::B(EitherUpgrade::A(u)))
                        .map_info(|info| EitherOutput::Second(EitherOutput::First(info))),
                });
            }
            Poll::Pending => (),
        };

        match self.identify_handler.poll(cx) {
            Poll::Ready(ProtocolsHandlerEvent::Custom(event)) => {
                return Poll::Ready(ProtocolsHandlerEvent::Custom(DelegateOut::Identify(
                    Box::new(event),
                )));
            }
            Poll::Ready(ProtocolsHandlerEvent::Close(event)) => {
                return Poll::Ready(ProtocolsHandlerEvent::Close(DelegateError::Identify(event)));
            }
            Poll::Ready(ProtocolsHandlerEvent::OutboundSubstreamRequest { protocol }) => {
                return Poll::Ready(ProtocolsHandlerEvent::OutboundSubstreamRequest {
                    protocol: protocol
                        .map_upgrade(|u| EitherUpgrade::B(EitherUpgrade::B(u)))
                        .map_info(|_| EitherOutput::Second(EitherOutput::Second(()))),
                });
            }
            Poll::Pending => (),
        };

        Poll::Pending
    }
}
