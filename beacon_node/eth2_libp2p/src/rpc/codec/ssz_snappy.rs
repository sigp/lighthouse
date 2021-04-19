use crate::rpc::methods::*;
use crate::rpc::{
    codec::base::OutboundCodec,
    protocol::{Encoding, Protocol, ProtocolId, RPCError, Version, ERROR_TYPE_MAX, ERROR_TYPE_MIN},
};
use crate::rpc::{RPCCodedResponse, RPCRequest, RPCResponse};
use libp2p::bytes::BytesMut;
use snap::read::FrameDecoder;
use snap::write::FrameEncoder;
use ssz::{Decode, Encode};
use ssz_types::VariableList;
use std::io::Cursor;
use std::io::ErrorKind;
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::sync::Arc;
use tokio_util::codec::{Decoder, Encoder};
use types::{
    EthSpec, ForkContext, ForkName, SignedBeaconBlock, SignedBeaconBlockAltair,
    SignedBeaconBlockBase,
};
use unsigned_varint::codec::Uvi;

/* Inbound Codec */

pub struct SSZSnappyInboundCodec<TSpec: EthSpec> {
    protocol: ProtocolId,
    inner: Uvi<usize>,
    len: Option<usize>,
    /// Maximum bytes that can be sent in one req/resp chunked responses.
    max_packet_size: usize,
    fork_context: Arc<ForkContext>,
    phantom: PhantomData<TSpec>,
}

impl<T: EthSpec> SSZSnappyInboundCodec<T> {
    pub fn new(
        protocol: ProtocolId,
        max_packet_size: usize,
        fork_context: Arc<ForkContext>,
    ) -> Self {
        let uvi_codec = Uvi::default();
        // this encoding only applies to ssz_snappy.
        debug_assert_eq!(protocol.encoding, Encoding::SSZSnappy);

        SSZSnappyInboundCodec {
            inner: uvi_codec,
            protocol,
            len: None,
            phantom: PhantomData,
            fork_context,
            max_packet_size,
        }
    }
}

// Encoder for inbound streams: Encodes RPC Responses sent to peers.
impl<TSpec: EthSpec> Encoder<RPCCodedResponse<TSpec>> for SSZSnappyInboundCodec<TSpec> {
    type Error = RPCError;

    fn encode(
        &mut self,
        item: RPCCodedResponse<TSpec>,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        let bytes = match &item {
            RPCCodedResponse::Success(resp) => match &resp {
                RPCResponse::Status(res) => res.as_ssz_bytes(),
                RPCResponse::BlocksByRange(res) => res.as_ssz_bytes(),
                RPCResponse::BlocksByRoot(res) => res.as_ssz_bytes(),
                RPCResponse::Pong(res) => res.data.as_ssz_bytes(),
                RPCResponse::MetaData(res) => res.as_ssz_bytes(),
            },
            RPCCodedResponse::Error(_, err) => err.as_ssz_bytes(),
            RPCCodedResponse::StreamTermination(_) => {
                unreachable!("Code error - attempting to encode a stream termination")
            }
        };
        // SSZ encoded bytes should be within `max_packet_size`
        if bytes.len() > self.max_packet_size {
            return Err(RPCError::InternalError(
                "attempting to encode data > max_packet_size",
            ));
        }

        // Add the context bytes if required
        if self.protocol.version == Version::V2 {
            if let RPCCodedResponse::Success(RPCResponse::BlocksByRange(ref res)) = item {
                if let SignedBeaconBlock::Altair { .. } = **res {
                    dst.extend_from_slice(&self.fork_context.to_context_bytes(ForkName::Altair));
                } else if let SignedBeaconBlock::Base { .. } = **res {
                    dst.extend_from_slice(&self.fork_context.to_context_bytes(ForkName::Base));
                }
            }

            if let RPCCodedResponse::Success(RPCResponse::BlocksByRoot(res)) = item {
                if let SignedBeaconBlock::Altair { .. } = *res {
                    dst.extend_from_slice(&self.fork_context.to_context_bytes(ForkName::Altair));
                } else if let SignedBeaconBlock::Base { .. } = *res {
                    dst.extend_from_slice(&self.fork_context.to_context_bytes(ForkName::Base));
                }
            }
        }

        // Inserts the length prefix of the uncompressed bytes into dst
        // encoded as a unsigned varint
        self.inner
            .encode(bytes.len(), dst)
            .map_err(RPCError::from)?;

        let mut writer = FrameEncoder::new(Vec::new());
        writer.write_all(&bytes).map_err(RPCError::from)?;
        writer.flush().map_err(RPCError::from)?;

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
        let length = if let Some(length) = self.len {
            length
        } else {
            // Decode the length of the uncompressed bytes from an unsigned varint
            // Note: length-prefix of > 10 bytes(uint64) would be a decoding error
            match self.inner.decode(src).map_err(RPCError::from)? {
                Some(length) => {
                    self.len = Some(length);
                    length
                }
                None => return Ok(None), // need more bytes to decode length
            }
        };

        // Should not attempt to decode rpc chunks with `length > max_packet_size` or not within bounds of
        // packet size for ssz container corresponding to `self.protocol`.
        let ssz_limits = self.protocol.rpc_request_limits();
        if length > self.max_packet_size || ssz_limits.is_out_of_bounds(length) {
            return Err(RPCError::InvalidData);
        }
        // Calculate worst case compression length for given uncompressed length
        let max_compressed_len = snap::raw::max_compress_len(length) as u64;

        // Create a limit reader as a wrapper that reads only upto `max_compressed_len` from `src`.
        let limit_reader = Cursor::new(src.as_ref()).take(max_compressed_len);
        let mut reader = FrameDecoder::new(limit_reader);
        let mut decoded_buffer = vec![0; length];

        match reader.read_exact(&mut decoded_buffer) {
            Ok(()) => {
                // `n` is how many bytes the reader read in the compressed stream
                let n = reader.get_ref().get_ref().position();
                self.len = None;
                let _read_bytes = src.split_to(n as usize);

                // We need not check that decoded_buffer.len() is within bounds here
                // since we have already checked `length` above.
                match self.protocol.version {
                    Version::V1 => match self.protocol.message_name {
                        Protocol::Status => Ok(Some(RPCRequest::Status(
                            StatusMessage::from_ssz_bytes(&decoded_buffer)?,
                        ))),
                        Protocol::Goodbye => Ok(Some(RPCRequest::Goodbye(
                            GoodbyeReason::from_ssz_bytes(&decoded_buffer)?,
                        ))),
                        Protocol::BlocksByRange => Ok(Some(RPCRequest::BlocksByRange(
                            BlocksByRangeRequest::from_ssz_bytes(&decoded_buffer)?,
                        ))),
                        Protocol::BlocksByRoot => {
                            Ok(Some(RPCRequest::BlocksByRoot(BlocksByRootRequest {
                                block_roots: VariableList::from_ssz_bytes(&decoded_buffer)?,
                            })))
                        }
                        Protocol::Ping => Ok(Some(RPCRequest::Ping(Ping {
                            data: u64::from_ssz_bytes(&decoded_buffer)?,
                        }))),
                        Protocol::MetaData => {
                            if !decoded_buffer.is_empty() {
                                Err(RPCError::InvalidData)
                            } else {
                                Ok(Some(RPCRequest::MetaData(PhantomData)))
                            }
                        }
                    },
                    // Receiving a Rpc request for protocol version 2 for range and root
                    Version::V2 => {
                        match self.protocol.message_name {
                            // Request type doesn't change, only response type
                            Protocol::BlocksByRange => Ok(Some(RPCRequest::BlocksByRange(
                                BlocksByRangeRequest::from_ssz_bytes(&decoded_buffer)?,
                            ))),
                            Protocol::BlocksByRoot => {
                                Ok(Some(RPCRequest::BlocksByRoot(BlocksByRootRequest {
                                    block_roots: VariableList::from_ssz_bytes(&decoded_buffer)?,
                                })))
                            }
                            _ => Err(RPCError::ErrorResponse(
                                RPCResponseErrorCode::InvalidRequest,
                                "Invalid v2 request".to_string(),
                            )),
                        }
                    }
                }
            }
            Err(e) => handle_error(e, reader.get_ref().get_ref().position(), max_compressed_len),
        }
    }
}

/* Outbound Codec: Codec for initiating RPC requests */
pub struct SSZSnappyOutboundCodec<TSpec: EthSpec> {
    inner: Uvi<usize>,
    len: Option<usize>,
    protocol: ProtocolId,
    /// Maximum bytes that can be sent in one req/resp chunked responses.
    max_packet_size: usize,
    context_bytes: Option<[u8; 4]>,
    fork_context: Arc<ForkContext>,
    phantom: PhantomData<TSpec>,
}

impl<TSpec: EthSpec> SSZSnappyOutboundCodec<TSpec> {
    pub fn new(
        protocol: ProtocolId,
        max_packet_size: usize,
        fork_context: Arc<ForkContext>,
    ) -> Self {
        let uvi_codec = Uvi::default();
        // this encoding only applies to ssz_snappy.
        debug_assert_eq!(protocol.encoding, Encoding::SSZSnappy);

        SSZSnappyOutboundCodec {
            inner: uvi_codec,
            protocol,
            max_packet_size,
            len: None,
            context_bytes: None,
            fork_context,
            phantom: PhantomData,
        }
    }
}

// Encoder for outbound streams: Encodes RPC Requests to peers
impl<TSpec: EthSpec> Encoder<RPCRequest<TSpec>> for SSZSnappyOutboundCodec<TSpec> {
    type Error = RPCError;

    fn encode(&mut self, item: RPCRequest<TSpec>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = match item {
            RPCRequest::Status(req) => req.as_ssz_bytes(),
            RPCRequest::Goodbye(req) => req.as_ssz_bytes(),
            RPCRequest::BlocksByRange(req) => req.as_ssz_bytes(),
            RPCRequest::BlocksByRoot(req) => req.block_roots.as_ssz_bytes(),
            RPCRequest::Ping(req) => req.as_ssz_bytes(),
            RPCRequest::MetaData(_) => return Ok(()), // no metadata to encode
        };
        // SSZ encoded bytes should be within `max_packet_size`
        if bytes.len() > self.max_packet_size {
            return Err(RPCError::InternalError(
                "attempting to encode data > max_packet_size",
            ));
        }

        // Inserts the length prefix of the uncompressed bytes into dst
        // encoded as a unsigned varint
        self.inner
            .encode(bytes.len(), dst)
            .map_err(RPCError::from)?;

        let mut writer = FrameEncoder::new(Vec::new());
        writer.write_all(&bytes).map_err(RPCError::from)?;
        writer.flush().map_err(RPCError::from)?;

        // Write compressed bytes to `dst`
        dst.extend_from_slice(writer.get_ref());
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
        // Read the context bytes if required
        if self.protocol.version == Version::V2 && self.context_bytes.is_none() {
            let context_bytes = src.split_to(4);
            let mut result = [0; 4];
            result.copy_from_slice(&context_bytes.as_ref());

            self.context_bytes = Some(result);
        }
        let length = if let Some(length) = self.len {
            length
        } else {
            // Decode the length of the uncompressed bytes from an unsigned varint
            // Note: length-prefix of > 10 bytes(uint64) would be a decoding error
            match self.inner.decode(src).map_err(RPCError::from)? {
                Some(length) => {
                    self.len = Some(length as usize);
                    length
                }
                None => return Ok(None), // need more bytes to decode length
            }
        };

        // Should not attempt to decode rpc chunks with `length > max_packet_size` or not within bounds of
        // packet size for ssz container corresponding to `self.protocol`.
        let ssz_limits = self.protocol.rpc_response_limits::<TSpec>();
        if length > self.max_packet_size || ssz_limits.is_out_of_bounds(length) {
            return Err(RPCError::InvalidData);
        }
        // Calculate worst case compression length for given uncompressed length
        let max_compressed_len = snap::raw::max_compress_len(length) as u64;
        // Create a limit reader as a wrapper that reads only upto `max_compressed_len` from `src`.
        let limit_reader = Cursor::new(src.as_ref()).take(max_compressed_len);
        let mut reader = FrameDecoder::new(limit_reader);

        let mut decoded_buffer = vec![0; length];

        match reader.read_exact(&mut decoded_buffer) {
            Ok(()) => {
                // `n` is how many bytes the reader read in the compressed stream
                let n = reader.get_ref().get_ref().position();
                self.len = None;
                let _read_bytes = src.split_to(n as usize);

                // We need not check that decoded_buffer.len() is within bounds here
                // since we have already checked `length` above.
                match self.protocol.version {
                    Version::V1 => match self.protocol.message_name {
                        Protocol::Status => Ok(Some(RPCResponse::Status(
                            StatusMessage::from_ssz_bytes(&decoded_buffer)?,
                        ))),
                        // This case should be unreachable as `Goodbye` has no response.
                        Protocol::Goodbye => Err(RPCError::InvalidData),
                        Protocol::BlocksByRange => Ok(Some(RPCResponse::BlocksByRange(Box::new(
                            SignedBeaconBlock::Base(SignedBeaconBlockBase::from_ssz_bytes(
                                &decoded_buffer,
                            )?),
                        )))),
                        Protocol::BlocksByRoot => Ok(Some(RPCResponse::BlocksByRoot(Box::new(
                            SignedBeaconBlock::Base(SignedBeaconBlockBase::from_ssz_bytes(
                                &decoded_buffer,
                            )?),
                        )))),
                        Protocol::Ping => Ok(Some(RPCResponse::Pong(Ping {
                            data: u64::from_ssz_bytes(&decoded_buffer)?,
                        }))),
                        Protocol::MetaData => Ok(Some(RPCResponse::MetaData(
                            MetaData::from_ssz_bytes(&decoded_buffer)?,
                        ))),
                    },
                    Version::V2 => {
                        let context_bytes = self.context_bytes.ok_or_else(|| {
                            RPCError::ErrorResponse(
                                RPCResponseErrorCode::InvalidRequest,
                                "No context bytes provided".to_string(),
                            )
                        })?;

                        let fork = self
                            .fork_context
                            .from_context_bytes(context_bytes)
                            .ok_or_else(|| {
                                RPCError::ErrorResponse(
                                    RPCResponseErrorCode::InvalidRequest,
                                    "Context bytes does not correspond to a valid fork".to_string(),
                                )
                            })?;
                        self.context_bytes = None;

                        match self.protocol.message_name {
                            Protocol::BlocksByRange => match fork {
                                ForkName::Altair => Ok(Some(RPCResponse::BlocksByRange(Box::new(
                                    SignedBeaconBlock::Altair(
                                        SignedBeaconBlockAltair::from_ssz_bytes(&decoded_buffer)?,
                                    ),
                                )))),

                                ForkName::Base => Ok(Some(RPCResponse::BlocksByRange(Box::new(
                                    SignedBeaconBlock::Base(SignedBeaconBlockBase::from_ssz_bytes(
                                        &decoded_buffer,
                                    )?),
                                )))),
                            },
                            Protocol::BlocksByRoot => match fork {
                                ForkName::Altair => Ok(Some(RPCResponse::BlocksByRoot(Box::new(
                                    SignedBeaconBlock::Altair(
                                        SignedBeaconBlockAltair::from_ssz_bytes(&decoded_buffer)?,
                                    ),
                                )))),
                                ForkName::Base => Ok(Some(RPCResponse::BlocksByRoot(Box::new(
                                    SignedBeaconBlock::Base(SignedBeaconBlockBase::from_ssz_bytes(
                                        &decoded_buffer,
                                    )?),
                                )))),
                            },

                            _ => Err(RPCError::ErrorResponse(
                                RPCResponseErrorCode::InvalidRequest,
                                "Invalid v2 request".to_string(),
                            )),
                        }
                    }
                }
            }
            Err(e) => handle_error(e, reader.get_ref().get_ref().position(), max_compressed_len),
        }
    }
}

impl<TSpec: EthSpec> OutboundCodec<RPCRequest<TSpec>> for SSZSnappyOutboundCodec<TSpec> {
    type CodecErrorType = ErrorType;

    fn decode_error(
        &mut self,
        src: &mut BytesMut,
    ) -> Result<Option<Self::CodecErrorType>, RPCError> {
        let length = if let Some(length) = self.len {
            length
        } else {
            // Decode the length of the uncompressed bytes from an unsigned varint
            match self.inner.decode(src).map_err(RPCError::from)? {
                Some(length) => {
                    self.len = Some(length as usize);
                    length
                }
                None => return Ok(None), // need more bytes to decode length
            }
        };

        // Should not attempt to decode rpc chunks with `length > max_packet_size` or not within bounds of
        // packet size for ssz container corresponding to `ErrorType`.
        if length > self.max_packet_size || length > *ERROR_TYPE_MAX || length < *ERROR_TYPE_MIN {
            return Err(RPCError::InvalidData);
        }

        // Calculate worst case compression length for given uncompressed length
        let max_compressed_len = snap::raw::max_compress_len(length) as u64;
        // Create a limit reader as a wrapper that reads only upto `max_compressed_len` from `src`.
        let limit_reader = Cursor::new(src.as_ref()).take(max_compressed_len);
        let mut reader = FrameDecoder::new(limit_reader);
        let mut decoded_buffer = vec![0; length];
        match reader.read_exact(&mut decoded_buffer) {
            Ok(()) => {
                // `n` is how many bytes the reader read in the compressed stream
                let n = reader.get_ref().get_ref().position();
                self.len = None;
                let _read_bytes = src.split_to(n as usize);
                Ok(Some(ErrorType(VariableList::from_ssz_bytes(
                    &decoded_buffer,
                )?)))
            }
            Err(e) => handle_error(e, reader.get_ref().get_ref().position(), max_compressed_len),
        }
    }
}

/// Handle errors that we get from decoding an RPC message from the stream.
/// `num_bytes_read` is the number of bytes the snappy decoder has read from the underlying stream.
/// `max_compressed_len` is the maximum compressed size for a given uncompressed size.
fn handle_error<T>(
    err: std::io::Error,
    num_bytes: u64,
    max_compressed_len: u64,
) -> Result<Option<T>, RPCError> {
    match err.kind() {
        ErrorKind::UnexpectedEof => {
            // If snappy has read `max_compressed_len` from underlying stream and still can't fill buffer, we have a malicious message.
            // Report as `InvalidData` so that malicious peer gets banned.
            if num_bytes >= max_compressed_len {
                Err(RPCError::InvalidData)
            } else {
                // Haven't received enough bytes to decode yet, wait for more
                Ok(None)
            }
        }
        _ => Err(err).map_err(RPCError::from),
    }
}
