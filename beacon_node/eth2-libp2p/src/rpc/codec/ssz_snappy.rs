use crate::rpc::methods::*;
use crate::rpc::{
    codec::base::OutboundCodec,
    protocol::{
        ProtocolId, RPCError, RPC_BLOCKS_BY_RANGE, RPC_BLOCKS_BY_ROOT, RPC_GOODBYE, RPC_STATUS,
    },
};
use crate::rpc::{ErrorMessage, RPCErrorResponse, RPCRequest, RPCResponse};
use libp2p::bytes::BytesMut;
use snap::read::FrameDecoder;
use snap::write::FrameEncoder;
use ssz::{Decode, Encode};
use std::io::Cursor;
use std::io::ErrorKind;
use std::io::{Read, Write};
use std::marker::PhantomData;
use tokio::codec::{Decoder, Encoder};
use types::{BeaconBlock, EthSpec};
use unsigned_varint::{decode, encode};

/* Inbound Codec */

pub struct SSZSnappyInboundCodec<TSpec: EthSpec> {
    decoder: snap::raw::Decoder,
    protocol: ProtocolId,
    phantom: PhantomData<TSpec>,
    /// Maximum bytes that can be sent in one req/resp chunked responses.
    max_packet_size: usize,
}

impl<T: EthSpec> SSZSnappyInboundCodec<T> {
    pub fn new(protocol: ProtocolId, max_packet_size: usize) -> Self {
        // this encoding only applies to ssz_snappy.
        debug_assert!(protocol.encoding.as_str() == "ssz_snappy");

        SSZSnappyInboundCodec {
            decoder: snap::raw::Decoder::new(),
            protocol,
            phantom: PhantomData,
            max_packet_size,
        }
    }
}

// Encoder for inbound streams: Encodes RPC Responses sent to peers.
impl<TSpec: EthSpec> Encoder for SSZSnappyInboundCodec<TSpec> {
    type Item = RPCErrorResponse<TSpec>;
    type Error = RPCError;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = match item {
            RPCErrorResponse::Success(resp) => match resp {
                RPCResponse::Status(res) => res.as_ssz_bytes(),
                RPCResponse::BlocksByRange(res) => res.as_ssz_bytes(),
                RPCResponse::BlocksByRoot(res) => res.as_ssz_bytes(),
            },
            RPCErrorResponse::InvalidRequest(err) => err.as_ssz_bytes(),
            RPCErrorResponse::ServerError(err) => err.as_ssz_bytes(),
            RPCErrorResponse::Unknown(err) => err.as_ssz_bytes(),
            RPCErrorResponse::StreamTermination(_) => {
                unreachable!("Code error - attempting to encode a stream termination")
            }
        };
        // SSZ encoded bytes should be within `max_packet_size`
        if bytes.len() > self.max_packet_size {
            return Err(RPCError::Custom(
                "attempting to encode data > max_packet_size".into(),
            ));
        }
        let mut writer = FrameEncoder::new(Vec::new());
        writer.write_all(&bytes).map_err(RPCError::from)?;
        writer.flush().map_err(RPCError::from)?;

        // Length prefix uncompressed bytes
        dst.extend_from_slice(encode::u64(bytes.len() as u64, &mut encode::u64_buffer()));
        // Write compressed bytes to `dst`
        dst.extend_from_slice(writer.get_ref());
        Ok(())
    }
}

// Decoder for inbound streams: Decodes RPC requests from peers
impl<TSpec: EthSpec> Decoder for SSZSnappyInboundCodec<TSpec> {
    type Item = RPCRequest<TSpec>;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.decoder.decompress_vec(src).map_err(RPCError::from) {
            Ok(packet) => match self.protocol.message_name.as_str() {
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
                _ => unreachable!("Cannot negotiate an unknown protocol"),
            },
            Err(e) => Err(e),
        }
    }
}

/* Outbound Codec: Codec for initiating RPC requests */
pub struct SSZSnappyOutboundCodec<TSpec: EthSpec> {
    encoder: snap::raw::Encoder,
    decoder: snap::raw::Decoder,
    len: Option<usize>,
    protocol: ProtocolId,
    /// Maximum bytes that can be sent in one req/resp chunked responses.
    max_packet_size: usize,
    phantom: PhantomData<TSpec>,
}

impl<TSpec: EthSpec> SSZSnappyOutboundCodec<TSpec> {
    pub fn new(protocol: ProtocolId, max_packet_size: usize) -> Self {
        // this encoding only applies to ssz_snappy.
        debug_assert!(protocol.encoding.as_str() == "ssz_snappy");

        SSZSnappyOutboundCodec {
            encoder: snap::raw::Encoder::new(),
            decoder: snap::raw::Decoder::new(),
            protocol,
            max_packet_size,
            len: None,
            phantom: PhantomData,
        }
    }
}

// Encoder for outbound streams: Encodes RPC Requests to peers
impl<TSpec: EthSpec> Encoder for SSZSnappyOutboundCodec<TSpec> {
    type Item = RPCRequest<TSpec>;
    type Error = RPCError;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = match item {
            RPCRequest::Status(req) => req.as_ssz_bytes(),
            RPCRequest::Goodbye(req) => req.as_ssz_bytes(),
            RPCRequest::BlocksByRange(req) => req.as_ssz_bytes(),
            RPCRequest::BlocksByRoot(req) => req.block_roots.as_ssz_bytes(),
            RPCRequest::Phantom(_) => unreachable!("Never encode phantom data"),
        };
        // Compressed RpcRequests are not UVI encoded since they don't have chunks.
        // Correspondingly on the receiving end, they are directly snappy uncompressed.
        let compressed_bytes = self.encoder.compress_vec(&bytes).map_err(RPCError::from)?;
        dst.extend_from_slice(&compressed_bytes);
        Ok(())
    }
}

// Decoder for outbound streams: Decodes RPC responses from peers.
//
// The majority of the decoding has now been pushed upstream due to the changing specification.
// We prefer to decode blocks and attestations with extra knowledge about the chain to perform
// faster verification checks before decoding entire blocks/attestations.
impl<TSpec: EthSpec> Decoder for SSZSnappyOutboundCodec<TSpec> {
    type Item = RPCResponse<TSpec>;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Decode the length of the uncompressed bytes
        if self.len.is_none() {
            match decode::u64(src) {
                Err(decode::Error::Insufficient) => return Ok(None), // Need more bytes to read len
                Err(decode::Error::Overflow) => {
                    return Err(RPCError::Custom(
                        "Overflow while reading uncompressed length from snappy frame".into(),
                    ))
                }
                Err(_) => {
                    return Err(RPCError::Custom(
                        "Failed to read length from snappy frame".into(),
                    ))
                }
                Ok((length, remaining)) => {
                    // split the incoming buffer to remove the read length bytes
                    let input_len = src.len();
                    let remaining_len = remaining.len();
                    src.split_to(input_len - remaining_len);
                    self.len = Some(length as usize);
                }
            }
        };

        // TODO: Double check that this never panics
        let length = self.len.expect("length should be Some");

        // Should not attempt to decode rpc chunks with length > max_packet_size
        if length > self.max_packet_size {
            return Err(RPCError::Custom(
                "attempting to decode data > max_packet_size".into(),
            ));
        }
        let mut reader = FrameDecoder::new(Cursor::new(&src));
        let mut decoded_buffer = vec![0; length];
        match reader.read_exact(&mut decoded_buffer) {
            Ok(()) => {
                // `n` is how many bytes the reader read in the compressed stream
                let n = reader.get_ref().position();
                self.len = None;
                src.split_to(n as usize);
                match self.protocol.message_name.as_str() {
                    RPC_STATUS => match self.protocol.version.as_str() {
                        "1" => Ok(Some(RPCResponse::Status(StatusMessage::from_ssz_bytes(
                            &decoded_buffer,
                        )?))),
                        _ => unreachable!("Cannot negotiate an unknown version"),
                    },
                    RPC_GOODBYE => {
                        Err(RPCError::InvalidProtocol("GOODBYE doesn't have a response"))
                    }
                    RPC_BLOCKS_BY_RANGE => match self.protocol.version.as_str() {
                        "1" => Ok(Some(RPCResponse::BlocksByRange(Box::new(
                            BeaconBlock::from_ssz_bytes(&decoded_buffer)?,
                        )))),
                        _ => unreachable!("Cannot negotiate an unknown version"),
                    },
                    RPC_BLOCKS_BY_ROOT => match self.protocol.version.as_str() {
                        "1" => Ok(Some(RPCResponse::BlocksByRoot(Box::new(
                            BeaconBlock::from_ssz_bytes(&decoded_buffer)?,
                        )))),
                        _ => unreachable!("Cannot negotiate an unknown version"),
                    },
                    _ => unreachable!("Cannot negotiate an unknown protocol"),
                }
            }
            Err(e) => match e.kind() {
                // Haven't received enough bytes to decode yet
                // TODO: check if this is the only Error variant where we return `Ok(None)`
                ErrorKind::UnexpectedEof => {
                    return Ok(None);
                }
                _ => return Err(e).map_err(RPCError::from),
            },
        }
    }
}

impl<TSpec: EthSpec> OutboundCodec for SSZSnappyOutboundCodec<TSpec> {
    type ErrorType = ErrorMessage;

    fn decode_error(&mut self, src: &mut BytesMut) -> Result<Option<Self::ErrorType>, RPCError> {
        match self.decoder.decompress_vec(src).map_err(RPCError::from) {
            Ok(packet) => Ok(Some(ErrorMessage::from_ssz_bytes(&packet)?)),
            Err(e) => Err(e),
        }
    }
}
