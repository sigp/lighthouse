use crate::rpc::methods::*;
use crate::rpc::{
    codec::base::OutboundCodec,
    protocol::{ProtocolId, RPCError},
};
use crate::rpc::{ErrorMessage, RPCErrorResponse, RPCRequest, RPCResponse};
use bytes::{Bytes, BytesMut};
use ssz::{Decode, Encode};
use tokio::codec::{Decoder, Encoder};
use unsigned_varint::codec::UviBytes;

/* Inbound Codec */

pub struct SSZInboundCodec {
    inner: UviBytes,
    protocol: ProtocolId,
}

impl SSZInboundCodec {
    pub fn new(protocol: ProtocolId, max_packet_size: usize) -> Self {
        let uvi_codec = UviBytes::default();
        uvi_codec.set_max_len(max_packet_size);

        // this encoding only applies to ssz.
        debug_assert!(protocol.encoding.as_str() == "ssz");

        SSZInboundCodec {
            inner: uvi_codec,
            protocol,
        }
    }
}

// Encoder for inbound
impl Encoder for SSZInboundCodec {
    type Item = RPCErrorResponse;
    type Error = RPCError;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = match item {
            RPCErrorResponse::Success(resp) => {
                match resp {
                    RPCResponse::Hello(res) => res.as_ssz_bytes(),
                    RPCResponse::Goodbye => unreachable!(),
                    RPCResponse::BeaconBlockRoots(res) => res.as_ssz_bytes(),
                    RPCResponse::BeaconBlockHeaders(res) => res.headers, // already raw bytes
                    RPCResponse::BeaconBlockBodies(res) => res.block_bodies, // already raw bytes
                    RPCResponse::BeaconChainState(res) => res.as_ssz_bytes(),
                }
            }
            RPCErrorResponse::EncodingError => vec![],
            RPCErrorResponse::InvalidRequest(err) => err.as_ssz_bytes(),
            RPCErrorResponse::ServerError(err) => err.as_ssz_bytes(),
            RPCErrorResponse::Unknown(err) => err.as_ssz_bytes(),
        };

        if !bytes.is_empty() {
            // length-prefix and return
            return self
                .inner
                .encode(Bytes::from(bytes), dst)
                .map_err(RPCError::from);
        }
        Ok(())
    }
}

// Decoder for inbound
impl Decoder for SSZInboundCodec {
    type Item = RPCRequest;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.inner.decode(src).map_err(RPCError::from) {
            Ok(Some(packet)) => match self.protocol.message_name.as_str() {
                "hello" => match self.protocol.version.as_str() {
                    "1.0.0" => Ok(Some(RPCRequest::Hello(HelloMessage::from_ssz_bytes(
                        &packet,
                    )?))),
                    _ => Err(RPCError::InvalidProtocol("Unknown HELLO version")),
                },
                "goodbye" => match self.protocol.version.as_str() {
                    "1.0.0" => Ok(Some(RPCRequest::Goodbye(Goodbye::from_ssz_bytes(&packet)?))),
                    _ => Err(RPCError::InvalidProtocol(
                        "Unknown GOODBYE version.as_str()",
                    )),
                },
                "beacon_block_roots" => match self.protocol.version.as_str() {
                    "1.0.0" => Ok(Some(RPCRequest::BeaconBlockRoots(
                        BeaconBlockRootsRequest::from_ssz_bytes(&packet)?,
                    ))),
                    _ => Err(RPCError::InvalidProtocol(
                        "Unknown BEACON_BLOCK_ROOTS version.",
                    )),
                },
                "beacon_block_headers" => match self.protocol.version.as_str() {
                    "1.0.0" => Ok(Some(RPCRequest::BeaconBlockHeaders(
                        BeaconBlockHeadersRequest::from_ssz_bytes(&packet)?,
                    ))),
                    _ => Err(RPCError::InvalidProtocol(
                        "Unknown BEACON_BLOCK_HEADERS version.",
                    )),
                },
                "beacon_block_bodies" => match self.protocol.version.as_str() {
                    "1.0.0" => Ok(Some(RPCRequest::BeaconBlockBodies(
                        BeaconBlockBodiesRequest::from_ssz_bytes(&packet)?,
                    ))),
                    _ => Err(RPCError::InvalidProtocol(
                        "Unknown BEACON_BLOCK_BODIES version.",
                    )),
                },
                "beacon_chain_state" => match self.protocol.version.as_str() {
                    "1.0.0" => Ok(Some(RPCRequest::BeaconChainState(
                        BeaconChainStateRequest::from_ssz_bytes(&packet)?,
                    ))),
                    _ => Err(RPCError::InvalidProtocol(
                        "Unknown BEACON_CHAIN_STATE version.",
                    )),
                },
            },
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/* Outbound Codec */

pub struct SSZOutboundCodec {
    inner: UviBytes,
    protocol: ProtocolId,
}

impl SSZOutboundCodec {
    pub fn new(protocol: ProtocolId, max_packet_size: usize) -> Self {
        let uvi_codec = UviBytes::default();
        uvi_codec.set_max_len(max_packet_size);

        // this encoding only applies to ssz.
        debug_assert!(protocol.encoding.as_str() == "ssz");

        SSZOutboundCodec {
            inner: uvi_codec,
            protocol,
        }
    }
}

// Encoder for outbound
impl Encoder for SSZOutboundCodec {
    type Item = RPCRequest;
    type Error = RPCError;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = match item {
            RPCRequest::Hello(req) => req.as_ssz_bytes(),
            RPCRequest::Goodbye(req) => req.as_ssz_bytes(),
            RPCRequest::BeaconBlockRoots(req) => req.as_ssz_bytes(),
            RPCRequest::BeaconBlockHeaders(req) => req.as_ssz_bytes(),
            RPCRequest::BeaconBlockBodies(req) => req.as_ssz_bytes(),
            RPCRequest::BeaconChainState(req) => req.as_ssz_bytes(),
        };
        // length-prefix
        self.inner
            .encode(bytes::Bytes::from(bytes), dst)
            .map_err(RPCError::from)
    }
}

// Decoder for outbound
impl Decoder for SSZOutboundCodec {
    type Item = RPCResponse;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.inner.decode(src).map_err(RPCError::from) {
            Ok(Some(packet)) => match self.protocol.message_name.as_str() {
                "hello" => match self.protocol.version.as_str() {
                    "1.0.0" => Ok(Some(RPCResponse::Hello(HelloMessage::from_ssz_bytes(
                        &packet,
                    )?))),
                    _ => Err(RPCError::InvalidProtocol("Unknown HELLO version.")),
                },
                "goodbye" => Err(RPCError::InvalidProtocol("GOODBYE doesn't have a response")),
                "beacon_block_roots" => match self.protocol.version.as_str() {
                    "1.0.0" => Ok(Some(RPCResponse::BeaconBlockRoots(
                        BeaconBlockRootsResponse::from_ssz_bytes(&packet)?,
                    ))),
                    _ => Err(RPCError::InvalidProtocol(
                        "Unknown BEACON_BLOCK_ROOTS version.",
                    )),
                },
                "beacon_block_headers" => match self.protocol.version.as_str() {
                    "1.0.0" => Ok(Some(RPCResponse::BeaconBlockHeaders(
                        BeaconBlockHeadersResponse {
                            headers: packet.to_vec(),
                        },
                    ))),
                    _ => Err(RPCError::InvalidProtocol(
                        "Unknown BEACON_BLOCK_HEADERS version.",
                    )),
                },
                "beacon_block_bodies" => match self.protocol.version.as_str() {
                    "1.0.0" => Ok(Some(RPCResponse::BeaconBlockBodies(
                        BeaconBlockBodiesResponse {
                            block_bodies: packet.to_vec(),
                        },
                    ))),
                    _ => Err(RPCError::InvalidProtocol(
                        "Unknown BEACON_BLOCK_BODIES version.",
                    )),
                },
                "beacon_chain_state" => match self.protocol.version.as_str() {
                    "1.0.0" => Ok(Some(RPCResponse::BeaconChainState(
                        BeaconChainStateResponse::from_ssz_bytes(&packet)?,
                    ))),
                    _ => Err(RPCError::InvalidProtocol(
                        "Unknown BEACON_CHAIN_STATE version.",
                    )),
                },
                _ => Err(RPCError::InvalidProtocol("Unknown method")),
            },
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl OutboundCodec for SSZOutboundCodec {
    type ErrorType = ErrorMessage;

    fn decode_error(&mut self, src: &mut BytesMut) -> Result<Option<Self::ErrorType>, RPCError> {
        match self.inner.decode(src).map_err(RPCError::from) {
            Ok(Some(packet)) => Ok(Some(ErrorMessage::from_ssz_bytes(&packet)?)),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }
}
