use crate::rpc::methods::*;
use crate::rpc::{
    codec::base::OutboundCodec,
    protocol::{
        ProtocolId, RPCError, RPC_BLOCKS_BY_RANGE, RPC_BLOCKS_BY_ROOT, RPC_GOODBYE, RPC_META_DATA,
        RPC_PING, RPC_STATUS,
    },
};
use crate::rpc::{ErrorMessage, RPCErrorResponse, RPCRequest, RPCResponse};
use libp2p::bytes::{BufMut, Bytes, BytesMut};
use ssz::{Decode, Encode};
use std::marker::PhantomData;
use tokio::codec::{Decoder, Encoder};
use types::{EthSpec, SignedBeaconBlock};
use unsigned_varint::codec::UviBytes;

/* Inbound Codec */

pub struct SSZInboundCodec<TSpec: EthSpec> {
    inner: UviBytes,
    protocol: ProtocolId,
    phantom: PhantomData<TSpec>,
}

impl<T: EthSpec> SSZInboundCodec<T> {
    pub fn new(protocol: ProtocolId, max_packet_size: usize) -> Self {
        let mut uvi_codec = UviBytes::default();
        uvi_codec.set_max_len(max_packet_size);

        // this encoding only applies to ssz.
        debug_assert!(protocol.encoding.as_str() == "ssz");

        SSZInboundCodec {
            inner: uvi_codec,
            protocol,
            phantom: PhantomData,
        }
    }
}

// Encoder for inbound streams: Encodes RPC Responses sent to peers.
impl<TSpec: EthSpec> Encoder for SSZInboundCodec<TSpec> {
    type Item = RPCErrorResponse<TSpec>;
    type Error = RPCError;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = match item {
            RPCErrorResponse::Success(resp) => match resp {
                RPCResponse::Status(res) => res.as_ssz_bytes(),
                RPCResponse::BlocksByRange(res) => res.as_ssz_bytes(),
                RPCResponse::BlocksByRoot(res) => res.as_ssz_bytes(),
                RPCResponse::Pong(res) => res.data.as_ssz_bytes(),
                RPCResponse::MetaData(res) => res.as_ssz_bytes(),
            },
            RPCErrorResponse::InvalidRequest(err) => err.as_ssz_bytes(),
            RPCErrorResponse::ServerError(err) => err.as_ssz_bytes(),
            RPCErrorResponse::Unknown(err) => err.as_ssz_bytes(),
            RPCErrorResponse::StreamTermination(_) => {
                unreachable!("Code error - attempting to encode a stream termination")
            }
        };
        if !bytes.is_empty() {
            // length-prefix and return
            return self
                .inner
                .encode(Bytes::from(bytes), dst)
                .map_err(RPCError::from);
        } else {
            // payload is empty, add a 0-byte length prefix
            dst.reserve(1);
            dst.put_u8(0);
        }
        Ok(())
    }
}

// Decoder for inbound streams: Decodes RPC requests from peers
impl<TSpec: EthSpec> Decoder for SSZInboundCodec<TSpec> {
    type Item = RPCRequest<TSpec>;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.inner.decode(src).map_err(RPCError::from) {
            Ok(Some(packet)) => match self.protocol.message_name.as_str() {
                RPC_STATUS => match self.protocol.version.as_str() {
                    "1" => Ok(Some(RPCRequest::Status(StatusMessage::from_ssz_bytes(
                        &packet,
                    )?))),
                    _ => unreachable!("Cannot negotiate an unknown version"),
                },
                RPC_GOODBYE => match self.protocol.version.as_str() {
                    "1" => Ok(Some(RPCRequest::Goodbye(GoodbyeReason::from_ssz_bytes(
                        &packet,
                    )?))),
                    _ => unreachable!("Cannot negotiate an unknown version"),
                },
                RPC_BLOCKS_BY_RANGE => match self.protocol.version.as_str() {
                    "1" => Ok(Some(RPCRequest::BlocksByRange(
                        BlocksByRangeRequest::from_ssz_bytes(&packet)?,
                    ))),
                    _ => unreachable!("Cannot negotiate an unknown version"),
                },
                RPC_BLOCKS_BY_ROOT => match self.protocol.version.as_str() {
                    "1" => Ok(Some(RPCRequest::BlocksByRoot(BlocksByRootRequest {
                        block_roots: Vec::from_ssz_bytes(&packet)?,
                    }))),
                    _ => unreachable!("Cannot negotiate an unknown version"),
                },
                RPC_PING => match self.protocol.version.as_str() {
                    "1" => Ok(Some(RPCRequest::Ping(Ping {
                        data: u64::from_ssz_bytes(&packet)?,
                    }))),
                    _ => unreachable!("Cannot negotiate an unknown version"),
                },
                RPC_META_DATA => match self.protocol.version.as_str() {
                    "1" => {
                        if packet.len() > 0 {
                            Err(RPCError::Custom(
                                "Get metadata request should be empty".into(),
                            ))
                        } else {
                            Ok(Some(RPCRequest::MetaData(PhantomData)))
                        }
                    }
                    _ => unreachable!("Cannot negotiate an unknown version"),
                },
                _ => unreachable!("Cannot negotiate an unknown protocol"),
            },
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/* Outbound Codec: Codec for initiating RPC requests */

pub struct SSZOutboundCodec<TSpec: EthSpec> {
    inner: UviBytes,
    protocol: ProtocolId,
    phantom: PhantomData<TSpec>,
}

impl<TSpec: EthSpec> SSZOutboundCodec<TSpec> {
    pub fn new(protocol: ProtocolId, max_packet_size: usize) -> Self {
        let mut uvi_codec = UviBytes::default();
        uvi_codec.set_max_len(max_packet_size);

        // this encoding only applies to ssz.
        debug_assert!(protocol.encoding.as_str() == "ssz");

        SSZOutboundCodec {
            inner: uvi_codec,
            protocol,
            phantom: PhantomData,
        }
    }
}

// Encoder for outbound streams: Encodes RPC Requests to peers
impl<TSpec: EthSpec> Encoder for SSZOutboundCodec<TSpec> {
    type Item = RPCRequest<TSpec>;
    type Error = RPCError;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = match item {
            RPCRequest::Status(req) => req.as_ssz_bytes(),
            RPCRequest::Goodbye(req) => req.as_ssz_bytes(),
            RPCRequest::BlocksByRange(req) => req.as_ssz_bytes(),
            RPCRequest::BlocksByRoot(req) => req.block_roots.as_ssz_bytes(),
            RPCRequest::Ping(req) => req.as_ssz_bytes(),
            RPCRequest::MetaData(_) => return Ok(()), // no metadata to encode
        };
        // length-prefix
        self.inner
            .encode(libp2p::bytes::Bytes::from(bytes), dst)
            .map_err(RPCError::from)
    }
}

// Decoder for outbound streams: Decodes RPC responses from peers.
//
// The majority of the decoding has now been pushed upstream due to the changing specification.
// We prefer to decode blocks and attestations with extra knowledge about the chain to perform
// faster verification checks before decoding entire blocks/attestations.
impl<TSpec: EthSpec> Decoder for SSZOutboundCodec<TSpec> {
    type Item = RPCResponse<TSpec>;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() == 1 && src[0] == 0_u8 {
            // the object is empty. We return the empty object if this is the case
            // clear the buffer and return an empty object
            src.clear();
            match self.protocol.message_name.as_str() {
                RPC_STATUS => match self.protocol.version.as_str() {
                    "1" => Err(RPCError::Custom(
                        "Status stream terminated unexpectedly".into(),
                    )), // cannot have an empty HELLO message. The stream has terminated unexpectedly
                    _ => unreachable!("Cannot negotiate an unknown version"),
                },
                RPC_GOODBYE => Err(RPCError::InvalidProtocol("GOODBYE doesn't have a response")),
                RPC_BLOCKS_BY_RANGE => match self.protocol.version.as_str() {
                    "1" => Err(RPCError::Custom(
                        "Status stream terminated unexpectedly, empty block".into(),
                    )), // cannot have an empty block message.
                    _ => unreachable!("Cannot negotiate an unknown version"),
                },
                RPC_BLOCKS_BY_ROOT => match self.protocol.version.as_str() {
                    "1" => Err(RPCError::Custom(
                        "Status stream terminated unexpectedly, empty block".into(),
                    )), // cannot have an empty block message.
                    _ => unreachable!("Cannot negotiate an unknown version"),
                },
                RPC_PING => match self.protocol.version.as_str() {
                    "1" => Err(RPCError::Custom(
                        "PING stream terminated unexpectedly".into(),
                    )), // cannot have an empty block message.
                    _ => unreachable!("Cannot negotiate an unknown version"),
                },
                RPC_META_DATA => match self.protocol.version.as_str() {
                    "1" => Err(RPCError::Custom(
                        "Metadata stream terminated unexpectedly".into(),
                    )), // cannot have an empty block message.
                    _ => unreachable!("Cannot negotiate an unknown version"),
                },
                _ => unreachable!("Cannot negotiate an unknown protocol"),
            }
        } else {
            match self.inner.decode(src).map_err(RPCError::from) {
                Ok(Some(mut packet)) => {
                    // take the bytes from the buffer
                    let raw_bytes = packet.take();

                    match self.protocol.message_name.as_str() {
                        RPC_STATUS => match self.protocol.version.as_str() {
                            "1" => Ok(Some(RPCResponse::Status(StatusMessage::from_ssz_bytes(
                                &raw_bytes,
                            )?))),
                            _ => unreachable!("Cannot negotiate an unknown version"),
                        },
                        RPC_GOODBYE => {
                            Err(RPCError::InvalidProtocol("GOODBYE doesn't have a response"))
                        }
                        RPC_BLOCKS_BY_RANGE => match self.protocol.version.as_str() {
                            "1" => Ok(Some(RPCResponse::BlocksByRange(Box::new(
                                SignedBeaconBlock::from_ssz_bytes(&raw_bytes)?,
                            )))),
                            _ => unreachable!("Cannot negotiate an unknown version"),
                        },
                        RPC_BLOCKS_BY_ROOT => match self.protocol.version.as_str() {
                            "1" => Ok(Some(RPCResponse::BlocksByRoot(Box::new(
                                SignedBeaconBlock::from_ssz_bytes(&raw_bytes)?,
                            )))),
                            _ => unreachable!("Cannot negotiate an unknown version"),
                        },
                        RPC_PING => match self.protocol.version.as_str() {
                            "1" => Ok(Some(RPCResponse::Pong(Ping {
                                data: u64::from_ssz_bytes(&raw_bytes)?,
                            }))),
                            _ => unreachable!("Cannot negotiate an unknown version"),
                        },
                        RPC_META_DATA => match self.protocol.version.as_str() {
                            "1" => Ok(Some(RPCResponse::MetaData(MetaData::from_ssz_bytes(
                                &raw_bytes,
                            )?))),
                            _ => unreachable!("Cannot negotiate an unknown version"),
                        },
                        _ => unreachable!("Cannot negotiate an unknown protocol"),
                    }
                }
                Ok(None) => Ok(None), // waiting for more bytes
                Err(e) => Err(e),
            }
        }
    }
}

impl<TSpec: EthSpec> OutboundCodec for SSZOutboundCodec<TSpec> {
    type ErrorType = ErrorMessage;

    fn decode_error(&mut self, src: &mut BytesMut) -> Result<Option<Self::ErrorType>, RPCError> {
        match self.inner.decode(src).map_err(RPCError::from) {
            Ok(Some(packet)) => Ok(Some(ErrorMessage::from_ssz_bytes(&packet)?)),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }
}
