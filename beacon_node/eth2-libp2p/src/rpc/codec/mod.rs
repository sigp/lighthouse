pub(crate) mod base;
pub(crate) mod ssz;
pub(crate) mod ssz_snappy;

use self::base::{BaseInboundCodec, BaseOutboundCodec};
use self::ssz::{SSZInboundCodec, SSZOutboundCodec};
use self::ssz_snappy::{SSZSnappyInboundCodec, SSZSnappyOutboundCodec};
use crate::rpc::protocol::RPCError;
use crate::rpc::{RPCErrorResponse, RPCRequest};
use libp2p::bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};
use types::EthSpec;

// Known types of codecs
pub enum InboundCodec<TSpec: EthSpec, TItem> {
    SSZSnappy(BaseInboundCodec<SSZSnappyInboundCodec<TSpec>, TSpec, TItem>),
    SSZ(BaseInboundCodec<SSZInboundCodec<TSpec>, TSpec, TItem>),
}

pub enum OutboundCodec<TSpec: EthSpec, TItem> {
    SSZSnappy(BaseOutboundCodec<SSZSnappyOutboundCodec<TSpec>, TSpec, TItem>),
    SSZ(BaseOutboundCodec<SSZOutboundCodec<TSpec>, TSpec, TItem>),
}

impl<T: EthSpec> Encoder<RPCErrorResponse<T>> for InboundCodec<T, RPCErrorResponse<T>> {
    type Error = RPCError;

    fn encode(&mut self, item: RPCErrorResponse<T>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match self {
            InboundCodec::SSZ(codec) => codec.encode(item, dst),
            InboundCodec::SSZSnappy(codec) => codec.encode(item, dst),
        }
    }
}

impl<TSpec: EthSpec> Decoder for InboundCodec<TSpec, RPCErrorResponse<TSpec>> {
    type Item = RPCRequest<TSpec>;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self {
            InboundCodec::SSZ(codec) => codec.decode(src),
            InboundCodec::SSZSnappy(codec) => codec.decode(src),
        }
    }
}

impl<TSpec: EthSpec> Encoder<RPCRequest<TSpec>> for OutboundCodec<TSpec, RPCRequest<TSpec>> {
    type Error = RPCError;

    fn encode(&mut self, item: RPCRequest<TSpec>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match self {
            OutboundCodec::SSZ(codec) => codec.encode(item, dst),
            OutboundCodec::SSZSnappy(codec) => codec.encode(item, dst),
        }
    }
}

impl<T: EthSpec> Decoder for OutboundCodec<T, RPCRequest<T>> {
    type Item = RPCErrorResponse<T>;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self {
            OutboundCodec::SSZ(codec) => codec.decode(src),
            OutboundCodec::SSZSnappy(codec) => codec.decode(src),
        }
    }
}
