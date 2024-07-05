pub(crate) mod base;
pub(crate) mod ssz_snappy;

use self::base::{BaseInboundCodec, BaseOutboundCodec};
use self::ssz_snappy::{SSZSnappyInboundCodec, SSZSnappyOutboundCodec};
use crate::rpc::protocol::RPCError;
use crate::rpc::{InboundRequest, OutboundRequest, RPCCodedResponse};
use libp2p::bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};
use types::EthSpec;

// Known types of codecs
pub enum InboundCodec<E: EthSpec> {
    SSZSnappy(BaseInboundCodec<SSZSnappyInboundCodec<E>, E>),
}

pub enum OutboundCodec<E: EthSpec> {
    SSZSnappy(BaseOutboundCodec<SSZSnappyOutboundCodec<E>, E>),
}

impl<E: EthSpec> Encoder<RPCCodedResponse<E>> for InboundCodec<E> {
    type Error = RPCError;

    fn encode(&mut self, item: RPCCodedResponse<E>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match self {
            InboundCodec::SSZSnappy(codec) => codec.encode(item, dst),
        }
    }
}

impl<E: EthSpec> Decoder for InboundCodec<E> {
    type Item = InboundRequest<E>;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self {
            InboundCodec::SSZSnappy(codec) => codec.decode(src),
        }
    }
}

impl<E: EthSpec> Encoder<OutboundRequest<E>> for OutboundCodec<E> {
    type Error = RPCError;

    fn encode(&mut self, item: OutboundRequest<E>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match self {
            OutboundCodec::SSZSnappy(codec) => codec.encode(item, dst),
        }
    }
}

impl<E: EthSpec> Decoder for OutboundCodec<E> {
    type Item = RPCCodedResponse<E>;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self {
            OutboundCodec::SSZSnappy(codec) => codec.decode(src),
        }
    }
}
