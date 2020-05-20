use crate::discovery::Discovery;
use crate::rpc::*;
use libp2p::{
    core::{
        either::{EitherError, EitherOutput},
        upgrade::{InboundUpgrade, OutboundUpgrade, SelectUpgrade},
    },
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

pub enum BHOutEvent<TSpec: EthSpec> {
    Delegate(DelegateOut<TSpec>),
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

/// Wrapper around the `ProtocolsHandler::InEvent` types of the behaviours.
/// An incoming event of this type is simply delegated to the corresponding behaviour's handler.
pub enum DelegateOut<TSpec: EthSpec> {
    Gossipsub(<GossipHandler as ProtocolsHandler>::OutEvent),
    RPC(<RPCHandler<TSpec> as ProtocolsHandler>::OutEvent),
    Identify(<IdentifyHandler as ProtocolsHandler>::OutEvent),
    Discovery(<DiscoveryHandler<TSpec> as ProtocolsHandler>::OutEvent),
}

// NOTE: the current implementation simply delegates all methods to the inner handler.
impl<TSpec: EthSpec> ProtocolsHandler for BehaviourHandler<TSpec> {
    type InEvent = BHInEvent<TSpec>;
    type OutEvent = <SelectHandler<TSpec> as ProtocolsHandler>::OutEvent;
    type Error = <SelectHandler<TSpec> as ProtocolsHandler>::Error;
    type InboundProtocol = SelectUpgrade<
        <GossipHandler as ProtocolsHandler>::InboundProtocol,
        SelectUpgrade<
            <RPCHandler<TSpec> as ProtocolsHandler>::InboundProtocol,
            SelectUpgrade<
                <IdentifyHandler as ProtocolsHandler>::InboundProtocol,
                <DiscoveryHandler<TSpec> as ProtocolsHandler>::InboundProtocol,
            >,
        >,
    >;
    type OutboundProtocol = <SelectHandler<TSpec> as ProtocolsHandler>::OutboundProtocol;
    type OutboundOpenInfo = <SelectHandler<TSpec> as ProtocolsHandler>::OutboundOpenInfo;

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        // get the listened protocols of each sub behaviour
        let gossip_proto = self.gossip_handler.listen_protocol();
        let rpc_proto = self.rpc_handler.listen_protocol();
        let identify_proto = self.identify_handler.listen_protocol();
        let discovery_proto = self.discovery_handler.listen_protocol();

        // asign the maximum timeout to the substream
        // TODO: simplify this, use Vecs maybe? Maps?
        // HandlersColl{handlers: Map someKindOfId -> Handler}
        let timeout = gossip_proto
            .timeout()
            .max(rpc_proto.timeout())
            .max(identify_proto.timeout())
            .max(discovery_proto.timeout())
            .clone();

        let select = SelectUpgrade::new(
            gossip_proto.into_upgrade().1,
            SelectUpgrade::new(
                rpc_proto.into_upgrade().1,
                SelectUpgrade::new(
                    identify_proto.into_upgrade().1,
                    discovery_proto.into_upgrade().1,
                ),
            ),
        );

        SubstreamProtocol::new(select).with_timeout(timeout)
    }

    fn inject_fully_negotiated_inbound(
        &mut self,
        out: <Self::InboundProtocol as InboundUpgrade<NegotiatedSubstream>>::Output,
    ) {
        // TODO: move this to vecs/maps
        // make outout = (id, out)?
        match out {
            EitherOutput::First(out) => self.gossip_handler.inject_fully_negotiated_inbound(out),
            EitherOutput::Second(EitherOutput::First(out)) => {
                self.rpc_handler.inject_fully_negotiated_inbound(out)
            }
            EitherOutput::Second(EitherOutput::Second(EitherOutput::First(out))) => {
                self.identify_handler.inject_fully_negotiated_inbound(out)
            }
            EitherOutput::Second(EitherOutput::Second(EitherOutput::Second(out))) => {
                self.discovery_handler.inject_fully_negotiated_inbound(out)
            }
        }
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

/*
 impl<TProto1, TProto2> ProtocolsHandler for ProtocolsHandlerSelect<TProto1, TProto2>
where
    TProto1: ProtocolsHandler,
    TProto2: ProtocolsHandler,
{
    type InEvent = EitherOutput<TProto1::InEvent, TProto2::InEvent>;
    type OutEvent = EitherOutput<TProto1::OutEvent, TProto2::OutEvent>;
    type Error = EitherError<TProto1::Error, TProto2::Error>;
    type InboundProtocol = SelectUpgrade<SendWrapper<<TProto1 as ProtocolsHandler>::InboundProtocol>, SendWrapper<<TProto2 as ProtocolsHandler>::InboundProtocol>>;
    type OutboundProtocol = EitherUpgrade<SendWrapper<TProto1::OutboundProtocol>, SendWrapper<TProto2::OutboundProtocol>>;
    type OutboundOpenInfo = EitherOutput<TProto1::OutboundOpenInfo, TProto2::OutboundOpenInfo>;

    #[inline]
    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        let proto1 = self.proto1.listen_protocol();
        let proto2 = self.proto2.listen_protocol();
        let timeout = std::cmp::max(proto1.timeout(), proto2.timeout()).clone();
        let choice = SelectUpgrade::new(SendWrapper(proto1.into_upgrade().1), SendWrapper(proto2.into_upgrade().1));
        SubstreamProtocol::new(choice).with_timeout(timeout)
    }

    fn inject_fully_negotiated_outbound(&mut self, protocol: <Self::OutboundProtocol as OutboundUpgradeSend>::Output, endpoint: Self::OutboundOpenInfo) {
        match (protocol, endpoint) {
            (EitherOutput::First(protocol), EitherOutput::First(info)) =>
                self.proto1.inject_fully_negotiated_outbound(protocol, info),
            (EitherOutput::Second(protocol), EitherOutput::Second(info)) =>
                self.proto2.inject_fully_negotiated_outbound(protocol, info),
            (EitherOutput::First(_), EitherOutput::Second(_)) =>
                panic!("wrong API usage: the protocol doesn't match the upgrade info"),
            (EitherOutput::Second(_), EitherOutput::First(_)) =>
                panic!("wrong API usage: the protocol doesn't match the upgrade info")
        }
    }

    fn inject_fully_negotiated_inbound(&mut self, protocol: <Self::InboundProtocol as InboundUpgradeSend>::Output) {
        match protocol {
            EitherOutput::First(protocol) =>
                self.proto1.inject_fully_negotiated_inbound(protocol),
            EitherOutput::Second(protocol) =>
                self.proto2.inject_fully_negotiated_inbound(protocol)
        }
    }

    #[inline]
    fn inject_event(&mut self, event: Self::InEvent) {
        match event {
            EitherOutput::First(event) => self.proto1.inject_event(event),
            EitherOutput::Second(event) => self.proto2.inject_event(event),
        }
    }

    #[inline]
    fn inject_dial_upgrade_error(&mut self, info: Self::OutboundOpenInfo, error: ProtocolsHandlerUpgrErr<<Self::OutboundProtocol as OutboundUpgradeSend>::Error>) {
        match (info, error) {
            (EitherOutput::First(info), ProtocolsHandlerUpgrErr::Timer) => {
                self.proto1.inject_dial_upgrade_error(info, ProtocolsHandlerUpgrErr::Timer)
            },
            (EitherOutput::First(info), ProtocolsHandlerUpgrErr::Timeout) => {
                self.proto1.inject_dial_upgrade_error(info, ProtocolsHandlerUpgrErr::Timeout)
            },
            (EitherOutput::First(info), ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Select(err))) => {
                self.proto1.inject_dial_upgrade_error(info, ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Select(err)))
            },
            (EitherOutput::First(info), ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Apply(EitherError::A(err)))) => {
                self.proto1.inject_dial_upgrade_error(info, ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Apply(err)))
            },
            (EitherOutput::First(_), ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Apply(EitherError::B(_)))) => {
                panic!("Wrong API usage; the upgrade error doesn't match the outbound open info");
            },
            (EitherOutput::Second(info), ProtocolsHandlerUpgrErr::Timeout) => {
                self.proto2.inject_dial_upgrade_error(info, ProtocolsHandlerUpgrErr::Timeout)
            },
            (EitherOutput::Second(info), ProtocolsHandlerUpgrErr::Timer) => {
                self.proto2.inject_dial_upgrade_error(info, ProtocolsHandlerUpgrErr::Timer)
            },
            (EitherOutput::Second(info), ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Select(err))) => {
                self.proto2.inject_dial_upgrade_error(info, ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Select(err)))
            },
            (EitherOutput::Second(info), ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Apply(EitherError::B(err)))) => {
                self.proto2.inject_dial_upgrade_error(info, ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Apply(err)))
            },
            (EitherOutput::Second(_), ProtocolsHandlerUpgrErr::Upgrade(UpgradeError::Apply(EitherError::A(_)))) => {
                panic!("Wrong API usage; the upgrade error doesn't match the outbound open info");
            },
        }
    }

    #[inline]
    fn connection_keep_alive(&self) -> KeepAlive {
        cmp::max(self.proto1.connection_keep_alive(), self.proto2.connection_keep_alive())
    }

    fn poll(&mut self, cx: &mut Context) -> Poll<ProtocolsHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::OutEvent, Self::Error>> {

        match self.proto1.poll(cx) {
            Poll::Ready(ProtocolsHandlerEvent::Custom(event)) => {
                return Poll::Ready(ProtocolsHandlerEvent::Custom(EitherOutput::First(event)));
            },
            Poll::Ready(ProtocolsHandlerEvent::Close(event)) => {
                return Poll::Ready(ProtocolsHandlerEvent::Close(EitherError::A(event)));
            },
            Poll::Ready(ProtocolsHandlerEvent::OutboundSubstreamRequest {
                protocol,
                info,
            }) => {
                return Poll::Ready(ProtocolsHandlerEvent::OutboundSubstreamRequest {
                    protocol: protocol.map_upgrade(|u| EitherUpgrade::A(SendWrapper(u))),
                    info: EitherOutput::First(info),
                });
            },
            Poll::Pending => ()
        };

        match self.proto2.poll(cx) {
            Poll::Ready(ProtocolsHandlerEvent::Custom(event)) => {
                return Poll::Ready(ProtocolsHandlerEvent::Custom(EitherOutput::Second(event)));
            },
            Poll::Ready(ProtocolsHandlerEvent::Close(event)) => {
                return Poll::Ready(ProtocolsHandlerEvent::Close(EitherError::B(event)));
            },
            Poll::Ready(ProtocolsHandlerEvent::OutboundSubstreamRequest {
                protocol,
                info,
            }) => {
                return Poll::Ready(ProtocolsHandlerEvent::OutboundSubstreamRequest {
                    protocol: protocol.map_upgrade(|u| EitherUpgrade::B(SendWrapper(u))),
                    info: EitherOutput::Second(info),
                });
            },
            Poll::Pending => ()
        };

        Poll::Pending
    }
}

 * */

/*EitherOutput*/

/*
/// Implements `AsyncRead` and `AsyncWrite` and dispatches all method calls to
/// either `First` or `Second`.
#[pin_project]
#[derive(Debug, Copy, Clone)]
pub enum EitherOutput<A, B> {
    First(#[pin] A),
    Second(#[pin] B),
}

impl<A, B> AsyncRead for EitherOutput<A, B>
where
    A: AsyncRead,
    B: AsyncRead,
{
    #[project]
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context, buf: &mut [u8]) -> Poll<Result<usize, IoError>> {
        #[project]
        match self.project() {
            EitherOutput::First(a) => AsyncRead::poll_read(a, cx, buf),
            EitherOutput::Second(b) => AsyncRead::poll_read(b, cx, buf),
        }
    }

    #[project]
    fn poll_read_vectored(self: Pin<&mut Self>, cx: &mut Context, bufs: &mut [IoSliceMut])
        -> Poll<Result<usize, IoError>>
    {
        #[project]
        match self.project() {
            EitherOutput::First(a) => AsyncRead::poll_read_vectored(a, cx, bufs),
            EitherOutput::Second(b) => AsyncRead::poll_read_vectored(b, cx, bufs),
        }
    }
}

impl<A, B> AsyncWrite for EitherOutput<A, B>
where
    A: AsyncWrite,
    B: AsyncWrite,
{
    #[project]
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<Result<usize, IoError>> {
        #[project]
        match self.project() {
            EitherOutput::First(a) => AsyncWrite::poll_write(a, cx, buf),
            EitherOutput::Second(b) => AsyncWrite::poll_write(b, cx, buf),
        }
    }

    #[project]
    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context, bufs: &[IoSlice])
        -> Poll<Result<usize, IoError>>
    {
        #[project]
        match self.project() {
            EitherOutput::First(a) => AsyncWrite::poll_write_vectored(a, cx, bufs),
            EitherOutput::Second(b) => AsyncWrite::poll_write_vectored(b, cx, bufs),
        }
    }

    #[project]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), IoError>> {
        #[project]
        match self.project() {
            EitherOutput::First(a) => AsyncWrite::poll_flush(a, cx),
            EitherOutput::Second(b) => AsyncWrite::poll_flush(b, cx),
        }
    }

    #[project]
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), IoError>> {
        #[project]
        match self.project() {
            EitherOutput::First(a) => AsyncWrite::poll_close(a, cx),
            EitherOutput::Second(b) => AsyncWrite::poll_close(b, cx),
        }
    }
}

  * */
