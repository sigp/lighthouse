pub(crate) mod base;
pub(crate) mod ssz;

use self::base::{BaseInboundCodec, BaseOutboundCodec};
use self::ssz::{SSZInboundCodec, SSZOutboundCodec};
use crate::rpc::protocol::RPCError;
use crate::rpc::{RPCErrorResponse, RPCRequest};
use bytes::BytesMut;
use tokio::codec::{Decoder, Encoder};

// Known types of codecs
pub enum InboundCodec {
    SSZ(BaseInboundCodec<SSZInboundCodec>),
}

pub enum OutboundCodec {
    SSZ(BaseOutboundCodec<SSZOutboundCodec>),
}

impl Encoder for InboundCodec {
    type Item = RPCErrorResponse;
    type Error = RPCError;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match self {
            InboundCodec::SSZ(codec) => codec.encode(item, dst),
        }
    }
}

impl Decoder for InboundCodec {
    type Item = RPCRequest;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self {
            InboundCodec::SSZ(codec) => codec.decode(src),
        }
    }
}

impl Encoder for OutboundCodec {
    type Item = RPCRequest;
    type Error = RPCError;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match self {
            OutboundCodec::SSZ(codec) => codec.encode(item, dst),
        }
    }
}

impl Decoder for OutboundCodec {
    type Item = RPCErrorResponse;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self {
            OutboundCodec::SSZ(codec) => codec.decode(src),
        }
    }
}
