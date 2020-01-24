use crate::rpc::methods::*;
use crate::rpc::{
    codec::base::OutboundCodec,
    protocol::{ProtocolId, RPCError},
};
use crate::rpc::{ErrorMessage, RPCErrorResponse, RPCRequest, RPCResponse};
use bytes::{BufMut, Bytes, BytesMut};
use ssz::{Decode, Encode};
use tokio::codec::{Decoder, Encoder};
use unsigned_varint::codec::UviBytes;

use snap;

/* Inbound Codec */

pub struct SSZSnappyInboundCodec {
    encoder: snap.Encoder,
    decoder: snap.Decoder,
    protocol: ProtocolId,
    max_packet_size
}

impl SSZSnappyInboundCodec {
    pub fn new(protocol: ProtocolId, max_packet_size: usize) -> Self {
        // this encoding only applies to ssz_snappy.
        debug_assert!(protocol.encoding.as_str() == "ssz_snappy");

        SSZSnappyInboundCodec {
            max_packet_size,
            encoder: snap.Encoder(),
            decoder: snap.Decoder(),
            protocol,
        }
    }
}

// Encoder for inbound
impl Encoder for SSZSnappyInboundCodec {
    type Item = RPCErrorResponse;
    type Error = RPCError;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = match item {
            RPCErrorResponse::Success(resp) => {
                match resp {
                    RPCResponse::Hello(res) => res.as_ssz_bytes(),
                    RPCResponse::BeaconBlocks(res) => res, // already raw bytes
                    RPCResponse::RecentBeaconBlocks(res) => res, // already raw bytes
                }
            }
            RPCErrorResponse::InvalidRequest(err) => err.as_ssz_bytes(),
            RPCErrorResponse::ServerError(err) => err.as_ssz_bytes(),
            RPCErrorResponse::Unknown(err) => err.as_ssz_bytes(),
        };

        if !bytes.is_empty() {
            // length-prefix and return
            return self
                .encoder
                .compress(Bytes::from(bytes), dst)
                .map_err(RPCError::from);
        } else {
            // payload is empty, add a 0-byte length prefix
            dst.reserve(1);
            dst.put_u8(0);
        }
        Ok(())
    }
}

// Decoder for inbound
impl Decoder for SSZSnappyInboundCodec {
    type Item = RPCRequest;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if(self.max_packet_size >= snap::decompress_len(src)){
        match self.decoder.decoder(src).map_err(RPCError::from) {
            Ok(Some(packet)) => match self.protocol.message_name.as_str() {
                "hello" => match self.protocol.version.as_str() {
                    "1" => Ok(Some(RPCRequest::Hello(HelloMessage::from_ssz_bytes(
                        &packet,
                    )?))),
                    _ => unreachable!("Cannot negotiate an unknown version"),
                },
                "goodbye" => match self.protocol.version.as_str() {
                    "1" => Ok(Some(RPCRequest::Goodbye(GoodbyeReason::from_ssz_bytes(
                        &packet,
                    )?))),
                    _ => unreachable!("Cannot negotiate an unknown version"),
                },
                "beacon_blocks" => match self.protocol.version.as_str() {
                    "1" => Ok(Some(RPCRequest::BeaconBlocks(
                        BeaconBlocksRequest::from_ssz_bytes(&packet)?,
                    ))),
                    _ => unreachable!("Cannot negotiate an unknown version"),
                },
                "recent_beacon_blocks" => match self.protocol.version.as_str() {
                    "1" => Ok(Some(RPCRequest::RecentBeaconBlocks(
                        RecentBeaconBlocksRequest::from_ssz_bytes(&packet)?,
                    ))),
                    _ => unreachable!("Cannot negotiate an unknown version"),
                },
                _ => unreachable!("Cannot negotiate an unknown protocol"),
            },
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }

        }
        else {
            Err("Packet is larger than the maximum packet size.")
        }
    }
}

/* Outbound Codec */

pub struct SSZSnappyOutboundCodec {
    encoder: snap.Encoder,
    decoder: snap.Decoder,
    protocol: ProtocolId,
}

impl SSZSnappyOutboundCodec {
    pub fn new(protocol: ProtocolId, max_packet_size: usize) -> Self {
        // this encoding only applies to ssz.
        debug_assert!(protocol.encoding.as_str() == "ssz_snappy");

        SSZSnappyOutboundCodec {
            max_packet_size,
            encoder: snap.Encoder(),
            decoder: snap.Decoder(),
            protocol,
        }
    }
}

// Encoder for outbound
impl Encoder for SSZSnappyOutboundCodec {
    type Item = RPCRequest;
    type Error = RPCError;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = match item {
            RPCRequest::Hello(req) => req.as_ssz_bytes(),
            RPCRequest::Goodbye(req) => req.as_ssz_bytes(),
            RPCRequest::BeaconBlocks(req) => req.as_ssz_bytes(),
            RPCRequest::RecentBeaconBlocks(req) => req.as_ssz_bytes(),
        };
        // length-prefix
        self.encoder
            .compress(bytes::Bytes::from(bytes), dst)
            .map_err(RPCError::from)
    }
}

// Decoder for outbound streams
//
// The majority of the decoding has now been pushed upstream due to the changing specification.
// We prefer to decode blocks and attestations with extra knowledge about the chain to perform
// faster verification checks before decoding entire blocks/attestations.
impl Decoder for SSZSnappyOutboundCodec {
    type Item = RPCResponse;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() == 1 && src[0] == 0_u8 {
            // the object is empty. We return the empty object if this is the case
            match self.protocol.message_name.as_str() {
                "hello" => match self.protocol.version.as_str() {
                    "1" => Err(RPCError::Custom(
                        "Hello stream terminated unexpectedly".into(),
                    )), // cannot have an empty HELLO message. The stream has terminated unexpectedly
                    _ => unreachable!("Cannot negotiate an unknown version"),
                },
                "goodbye" => Err(RPCError::InvalidProtocol("GOODBYE doesn't have a response")),
                "beacon_blocks" => match self.protocol.version.as_str() {
                    "1" => Ok(Some(RPCResponse::BeaconBlocks(Vec::new()))),
                    _ => unreachable!("Cannot negotiate an unknown version"),
                },
                "recent_beacon_blocks" => match self.protocol.version.as_str() {
                    "1" => Ok(Some(RPCResponse::RecentBeaconBlocks(Vec::new()))),
                    _ => unreachable!("Cannot negotiate an unknown version"),
                },
                _ => unreachable!("Cannot negotiate an unknown protocol"),
            }
        } else {
            if (snap::decompress_len(src)) {
                match self.decoder.decompress(src).map_err(RPCError::from) {
                    Ok(Some(packet)) => match self.protocol.message_name.as_str() {
                        "hello" => match self.protocol.version.as_str() {
                            "1" => Ok(Some(RPCResponse::Hello(HelloMessage::from_ssz_bytes(
                                &packet,
                            )?))),
                            _ => unreachable!("Cannot negotiate an unknown version"),
                        },
                        "goodbye" => Err(RPCError::InvalidProtocol("GOODBYE doesn't have a response")),
                        "beacon_blocks" => match self.protocol.version.as_str() {
                            "1" => Ok(Some(RPCResponse::BeaconBlocks(packet.to_vec()))),
                            _ => unreachable!("Cannot negotiate an unknown version"),
                        },
                        "recent_beacon_blocks" => match self.protocol.version.as_str() {
                            "1" => Ok(Some(RPCResponse::RecentBeaconBlocks(packet.to_vec()))),
                            _ => unreachable!("Cannot negotiate an unknown version"),
                        },
                        _ => unreachable!("Cannot negotiate an unknown protocol"),
                    },
                    Ok(None) => Ok(None), // waiting for more bytes
                    Err(e) => Err(e),
                }
            }
            else {
                Err("Packet is larger than the maximum packet size.")
            }
            
        }
    }
}

impl OutboundCodec for SSZSnappyOutboundCodec {
    type ErrorType = ErrorMessage;

    fn decode_error(&mut self, src: &mut BytesMut) -> Result<Option<Self::ErrorType>, RPCError> {
        match self.decoder.decompress(src).map_err(RPCError::from) {
            Ok(Some(packet)) => Ok(Some(ErrorMessage::from_ssz_bytes(&packet)?)),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

// TODO
// Test implementation
// Send out a goodbye request with the system -> Compare the request with "SNAPPY_REFERENCE_ON_CLI(normal goodbye request) ==  outgoing request"
// https://github.com/sigp/lighthouse/blob/master/beacon_node/eth2-libp2p/tests/rpc_tests.rs can be used with a prioritized snappy protocol