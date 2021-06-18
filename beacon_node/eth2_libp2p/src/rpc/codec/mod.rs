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
pub enum InboundCodec<TSpec: EthSpec> {
    SSZSnappy(BaseInboundCodec<SSZSnappyInboundCodec<TSpec>, TSpec>),
}

pub enum OutboundCodec<TSpec: EthSpec> {
    SSZSnappy(BaseOutboundCodec<SSZSnappyOutboundCodec<TSpec>, TSpec>),
}

impl<T: EthSpec> Encoder<RPCCodedResponse<T>> for InboundCodec<T> {
    type Error = RPCError;

    fn encode(&mut self, item: RPCCodedResponse<T>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match self {
            InboundCodec::SSZSnappy(codec) => codec.encode(item, dst),
        }
    }
}

impl<TSpec: EthSpec> Decoder for InboundCodec<TSpec> {
    type Item = InboundRequest<TSpec>;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self {
            InboundCodec::SSZSnappy(codec) => codec.decode(src),
        }
    }
}

impl<TSpec: EthSpec> Encoder<OutboundRequest<TSpec>> for OutboundCodec<TSpec> {
    type Error = RPCError;

    fn encode(
        &mut self,
        item: OutboundRequest<TSpec>,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        match self {
            OutboundCodec::SSZSnappy(codec) => codec.encode(item, dst),
        }
    }
}

impl<T: EthSpec> Decoder for OutboundCodec<T> {
    type Item = RPCCodedResponse<T>;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self {
            OutboundCodec::SSZSnappy(codec) => codec.decode(src),
        }
    }
}
