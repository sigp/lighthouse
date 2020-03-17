pub(crate) mod base;
pub(crate) mod ssz;

use self::base::{BaseInboundCodec, BaseOutboundCodec};
use self::ssz::{SSZInboundCodec, SSZOutboundCodec};
use crate::rpc::protocol::RPCError;
use crate::rpc::{RPCErrorResponse, RPCRequest};
use libp2p::bytes::BytesMut;
use tokio::codec::{Decoder, Encoder};
use types::EthSpec;

// Known types of codecs
pub enum InboundCodec<TSpec: EthSpec> {
    SSZ(BaseInboundCodec<SSZInboundCodec<TSpec>, TSpec>),
}

pub enum OutboundCodec<TSpec: EthSpec> {
    SSZ(BaseOutboundCodec<SSZOutboundCodec<TSpec>, TSpec>),
}

impl<T: EthSpec> Encoder for InboundCodec<T> {
    type Item = RPCErrorResponse<T>;
    type Error = RPCError;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match self {
            InboundCodec::SSZ(codec) => codec.encode(item, dst),
        }
    }
}

impl<TSpec: EthSpec> Decoder for InboundCodec<TSpec> {
    type Item = RPCRequest<TSpec>;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self {
            InboundCodec::SSZ(codec) => codec.decode(src),
        }
    }
}

impl<TSpec: EthSpec> Encoder for OutboundCodec<TSpec> {
    type Item = RPCRequest<TSpec>;
    type Error = RPCError;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match self {
            OutboundCodec::SSZ(codec) => codec.encode(item, dst),
        }
    }
}

impl<T: EthSpec> Decoder for OutboundCodec<T> {
    type Item = RPCErrorResponse<T>;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self {
            OutboundCodec::SSZ(codec) => codec.decode(src),
        }
    }
}
