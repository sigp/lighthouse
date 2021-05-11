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
        if self.protocol.has_context_bytes() {
            if let RPCCodedResponse::Success(RPCResponse::BlocksByRange(ref res)) = item {
                if let SignedBeaconBlock::Altair { .. } = **res {
                    // Altair context being `None` implies that "altair never happened".
                    // This code should be unreachable if altair is disabled since only Version::V1 would be valid in that case.
                    if let Some(ref altair_context) =
                        self.fork_context.to_context_bytes(ForkName::Altair)
                    {
                        dst.extend_from_slice(altair_context);
                    }
                } else if let SignedBeaconBlock::Base { .. } = **res {
                    dst.extend_from_slice(&self.fork_context.genesis_context_bytes());
                }
            }

            if let RPCCodedResponse::Success(RPCResponse::BlocksByRoot(res)) = item {
                if let SignedBeaconBlock::Altair { .. } = *res {
                    // Altair context being `None` implies that "altair never happened".
                    // This code should be unreachable if altair is disabled since only Version::V1 would be valid in that case.
                    if let Some(ref altair_context) =
                        self.fork_context.to_context_bytes(ForkName::Altair)
                    {
                        dst.extend_from_slice(altair_context);
                    }
                } else if let SignedBeaconBlock::Base { .. } = *res {
                    dst.extend_from_slice(&self.fork_context.genesis_context_bytes());
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
                    // Receiving a Rpc request for protocol version 2 for range and root requests
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
                                format!(
                                    "{} does not support version 2",
                                    self.protocol.message_name
                                ),
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
    /// The fork name corresponding to the received context bytes.
    fork_name: Option<ForkName>,
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
            fork_name: None,
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
        if self.protocol.has_context_bytes() && self.fork_name.is_none() {
            if src.len() >= 4 {
                let context_bytes = src.split_to(4);
                let mut result = [0; 4];
                result.copy_from_slice(&context_bytes.as_ref());
                self.fork_name = Some(context_bytes_to_fork_name(
                    result,
                    self.fork_context.clone(),
                )?);
            } else {
                return Ok(None);
            }
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
                    Version::V2 => match self.protocol.message_name {
                        Protocol::BlocksByRange => {
                            match self.fork_name.take().ok_or_else(|| {
                                RPCError::ErrorResponse(
                                    RPCResponseErrorCode::InvalidRequest,
                                    format!(
                                        "No context bytes provided for {} response",
                                        self.protocol.message_name
                                    ),
                                )
                            })? {
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
                            }
                        }
                        Protocol::BlocksByRoot => match self.fork_name.take().ok_or_else(|| {
                            RPCError::ErrorResponse(
                                RPCResponseErrorCode::InvalidRequest,
                                format!(
                                    "No context bytes provided for {} response",
                                    self.protocol.message_name
                                ),
                            )
                        })? {
                            ForkName::Altair => Ok(Some(RPCResponse::BlocksByRoot(Box::new(
                                SignedBeaconBlock::Altair(SignedBeaconBlockAltair::from_ssz_bytes(
                                    &decoded_buffer,
                                )?),
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
                    },
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

/// Takes the context bytes and a fork_context and returns the corresponding fork_name.
fn context_bytes_to_fork_name(
    context_bytes: [u8; 4],
    fork_context: Arc<ForkContext>,
) -> Result<ForkName, RPCError> {
    fork_context
        .from_context_bytes(context_bytes)
        .cloned()
        .ok_or_else(|| {
            RPCError::ErrorResponse(
                RPCResponseErrorCode::InvalidRequest,
                "Context bytes does not correspond to a valid fork".to_string(),
            )
        })
}
#[cfg(test)]
mod tests {

    use super::*;
    use crate::rpc::{protocol::*, MetaData};
    use crate::{
        rpc::{methods::StatusMessage, Ping, RPCResponseErrorCode},
        types::EnrBitfield,
    };
    use std::sync::Arc;
    use types::{
        BeaconBlock, BeaconBlockAltair, BeaconBlockBase, Epoch, ForkContext, Hash256, Signature,
        SignedBeaconBlock, Slot,
    };

    use snap::write::FrameEncoder;
    use ssz::Encode;
    use std::io::Write;

    type Spec = types::MainnetEthSpec;

    fn fork_context() -> ForkContext {
        ForkContext::new(Hash256::zero(), &Spec::default_spec())
    }

    fn base_block() -> SignedBeaconBlock<Spec> {
        let full_block = BeaconBlock::Base(BeaconBlockBase::<Spec>::full(&Spec::default_spec()));
        SignedBeaconBlock::from_block(full_block, Signature::empty())
    }

    fn altair_block() -> SignedBeaconBlock<Spec> {
        let full_block =
            BeaconBlock::Altair(BeaconBlockAltair::<Spec>::full(&Spec::default_spec()));
        SignedBeaconBlock::from_block(full_block, Signature::empty())
    }

    fn status_message() -> StatusMessage {
        StatusMessage {
            fork_digest: [0; 4],
            finalized_root: Hash256::from_low_u64_be(0),
            finalized_epoch: Epoch::new(1),
            head_root: Hash256::from_low_u64_be(0),
            head_slot: Slot::new(1),
        }
    }

    fn ping_message() -> Ping {
        Ping { data: 1 }
    }

    fn metadata() -> MetaData<Spec> {
        MetaData {
            seq_number: 1,
            attnets: EnrBitfield::<Spec>::default(),
        }
    }

    /// Encodes the given protocol response as bytes.
    fn encode(
        protocol: Protocol,
        version: Version,
        message: RPCCodedResponse<Spec>,
    ) -> Result<BytesMut, RPCError> {
        let max_packet_size = 1_048_576;
        let snappy_protocol_id = ProtocolId::new(protocol, version, Encoding::SSZSnappy);
        let fork_context = Arc::new(fork_context());

        let mut buf = BytesMut::new();
        let mut snappy_inbound_codec =
            SSZSnappyInboundCodec::<Spec>::new(snappy_protocol_id, max_packet_size, fork_context);

        snappy_inbound_codec.encode(message, &mut buf)?;
        Ok(buf)
    }

    /// Attempts to decode the given protocol bytes as an rpc response
    fn decode(
        protocol: Protocol,
        version: Version,
        message: &mut BytesMut,
    ) -> Result<Option<RPCResponse<Spec>>, RPCError> {
        let max_packet_size = 1_048_576;
        let snappy_protocol_id = ProtocolId::new(protocol, version, Encoding::SSZSnappy);
        let fork_context = Arc::new(fork_context());
        let mut snappy_outbound_codec =
            SSZSnappyOutboundCodec::<Spec>::new(snappy_protocol_id, max_packet_size, fork_context);
        // decode message just as snappy message
        snappy_outbound_codec.decode(message)
    }

    /// Encodes the provided protocol message as bytes and tries to decode the encoding bytes.
    fn encode_then_decode(
        protocol: Protocol,
        version: Version,
        message: RPCCodedResponse<Spec>,
    ) -> Result<Option<RPCResponse<Spec>>, RPCError> {
        let mut encoded = encode(protocol, version.clone(), message)?;
        decode(protocol, version, &mut encoded)
    }

    // Test RPCResponse encoding/decoding for V1 messages
    #[test]
    fn test_encode_then_decode_v1() {
        assert_eq!(
            encode_then_decode(
                Protocol::Status,
                Version::V1,
                RPCCodedResponse::Success(RPCResponse::Status(status_message()))
            ),
            Ok(Some(RPCResponse::Status(status_message())))
        );

        assert_eq!(
            encode_then_decode(
                Protocol::Ping,
                Version::V1,
                RPCCodedResponse::Success(RPCResponse::Pong(ping_message()))
            ),
            Ok(Some(RPCResponse::Pong(ping_message())))
        );

        assert_eq!(
            encode_then_decode(
                Protocol::BlocksByRange,
                Version::V1,
                RPCCodedResponse::Success(RPCResponse::BlocksByRange(Box::new(base_block())))
            ),
            Ok(Some(RPCResponse::BlocksByRange(Box::new(base_block()))))
        );

        assert!(
            matches!(
                encode_then_decode(
                    Protocol::BlocksByRange,
                    Version::V1,
                    RPCCodedResponse::Success(RPCResponse::BlocksByRange(Box::new(altair_block()))),
                )
                .unwrap_err(),
                RPCError::SSZDecodeError(_)
            ),
            "altair block cannot be decoded with blocks by range V1 version"
        );

        assert_eq!(
            encode_then_decode(
                Protocol::BlocksByRoot,
                Version::V1,
                RPCCodedResponse::Success(RPCResponse::BlocksByRoot(Box::new(base_block())))
            ),
            Ok(Some(RPCResponse::BlocksByRoot(Box::new(base_block()))))
        );

        assert!(
            matches!(
                encode_then_decode(
                    Protocol::BlocksByRoot,
                    Version::V1,
                    RPCCodedResponse::Success(RPCResponse::BlocksByRoot(Box::new(altair_block()))),
                )
                .unwrap_err(),
                RPCError::SSZDecodeError(_)
            ),
            "altair block cannot be decoded with blocks by range V1 version"
        );

        assert_eq!(
            encode_then_decode(
                Protocol::MetaData,
                Version::V1,
                RPCCodedResponse::Success(RPCResponse::MetaData(metadata())),
            ),
            Ok(Some(RPCResponse::MetaData(metadata()))),
        );

        // TODO: add metadataV2 response failure case
    }

    #[test]
    fn test_encode_then_decode_v2() {
        assert!(
            matches!(
                encode_then_decode(
                    Protocol::Status,
                    Version::V2,
                    RPCCodedResponse::Success(RPCResponse::Status(status_message())),
                )
                .unwrap_err(),
                RPCError::ErrorResponse(RPCResponseErrorCode::InvalidRequest, _),
            ),
            "status does not have V2 message"
        );

        assert!(
            matches!(
                encode_then_decode(
                    Protocol::Ping,
                    Version::V2,
                    RPCCodedResponse::Success(RPCResponse::Pong(ping_message())),
                )
                .unwrap_err(),
                RPCError::ErrorResponse(RPCResponseErrorCode::InvalidRequest, _),
            ),
            "ping does not have V2 message"
        );

        assert_eq!(
            encode_then_decode(
                Protocol::BlocksByRange,
                Version::V2,
                RPCCodedResponse::Success(RPCResponse::BlocksByRange(Box::new(base_block())))
            ),
            Ok(Some(RPCResponse::BlocksByRange(Box::new(base_block()))))
        );

        assert_eq!(
            encode_then_decode(
                Protocol::BlocksByRange,
                Version::V2,
                RPCCodedResponse::Success(RPCResponse::BlocksByRange(Box::new(altair_block())))
            ),
            Ok(Some(RPCResponse::BlocksByRange(Box::new(altair_block()))))
        );

        assert_eq!(
            encode_then_decode(
                Protocol::BlocksByRoot,
                Version::V2,
                RPCCodedResponse::Success(RPCResponse::BlocksByRoot(Box::new(base_block())))
            ),
            Ok(Some(RPCResponse::BlocksByRoot(Box::new(base_block()))))
        );

        assert_eq!(
            encode_then_decode(
                Protocol::BlocksByRoot,
                Version::V2,
                RPCCodedResponse::Success(RPCResponse::BlocksByRoot(Box::new(altair_block())))
            ),
            Ok(Some(RPCResponse::BlocksByRoot(Box::new(altair_block()))))
        );
    }

    #[test]
    fn test_context_bytes_v2() {
        let fork_context = fork_context();

        // Removing context bytes for v2 messages should error
        let mut encoded_bytes = encode(
            Protocol::BlocksByRange,
            Version::V2,
            RPCCodedResponse::Success(RPCResponse::BlocksByRange(Box::new(base_block()))),
        )
        .unwrap();

        let _ = encoded_bytes.split_to(4);

        assert!(matches!(
            decode(Protocol::BlocksByRange, Version::V2, &mut encoded_bytes).unwrap_err(),
            RPCError::ErrorResponse(RPCResponseErrorCode::InvalidRequest, _),
        ));

        let mut encoded_bytes = encode(
            Protocol::BlocksByRoot,
            Version::V2,
            RPCCodedResponse::Success(RPCResponse::BlocksByRoot(Box::new(base_block()))),
        )
        .unwrap();

        let _ = encoded_bytes.split_to(4);

        assert!(matches!(
            decode(Protocol::BlocksByRange, Version::V2, &mut encoded_bytes).unwrap_err(),
            RPCError::ErrorResponse(RPCResponseErrorCode::InvalidRequest, _),
        ));

        // Trying to decode a base block with altair context bytes should give ssz decoding error
        let mut encoded_bytes = encode(
            Protocol::BlocksByRange,
            Version::V2,
            RPCCodedResponse::Success(RPCResponse::BlocksByRange(Box::new(base_block()))),
        )
        .unwrap();

        let mut wrong_fork_bytes = BytesMut::new();
        wrong_fork_bytes
            .extend_from_slice(&fork_context.to_context_bytes(ForkName::Altair).unwrap());
        wrong_fork_bytes.extend_from_slice(&encoded_bytes.split_off(4));

        assert!(matches!(
            decode(Protocol::BlocksByRange, Version::V2, &mut wrong_fork_bytes).unwrap_err(),
            RPCError::SSZDecodeError(_),
        ));

        // Trying to decode an altair block with base context bytes should give ssz decoding error
        let mut encoded_bytes = encode(
            Protocol::BlocksByRoot,
            Version::V2,
            RPCCodedResponse::Success(RPCResponse::BlocksByRoot(Box::new(altair_block()))),
        )
        .unwrap();

        let mut wrong_fork_bytes = BytesMut::new();
        wrong_fork_bytes.extend_from_slice(&fork_context.to_context_bytes(ForkName::Base).unwrap());
        wrong_fork_bytes.extend_from_slice(&encoded_bytes.split_off(4));

        assert!(matches!(
            decode(Protocol::BlocksByRange, Version::V2, &mut wrong_fork_bytes).unwrap_err(),
            RPCError::SSZDecodeError(_),
        ));

        // Adding context bytes to Protocols that don't require it should return an error
        let mut encoded_bytes = BytesMut::new();
        encoded_bytes.extend_from_slice(&fork_context.to_context_bytes(ForkName::Altair).unwrap());
        encoded_bytes.extend_from_slice(
            &encode(
                Protocol::MetaData,
                Version::V2,
                RPCCodedResponse::Success(RPCResponse::MetaData(metadata())),
            )
            .unwrap(),
        );

        assert!(decode(Protocol::MetaData, Version::V2, &mut encoded_bytes).is_err());

        // Sending context bytes which do not correspond to any fork should return an error
        let mut encoded_bytes = encode(
            Protocol::BlocksByRoot,
            Version::V2,
            RPCCodedResponse::Success(RPCResponse::BlocksByRoot(Box::new(base_block()))),
        )
        .unwrap();

        let mut wrong_fork_bytes = BytesMut::new();
        wrong_fork_bytes.extend_from_slice(&[42, 42, 42, 42]);
        wrong_fork_bytes.extend_from_slice(&encoded_bytes.split_off(4));

        assert!(matches!(
            decode(Protocol::BlocksByRange, Version::V2, &mut wrong_fork_bytes).unwrap_err(),
            RPCError::ErrorResponse(RPCResponseErrorCode::InvalidRequest, _),
        ));

        // Sending bytes less than context bytes length should wait for more bytes by returning `Ok(None)`
        let mut encoded_bytes = encode(
            Protocol::BlocksByRoot,
            Version::V2,
            RPCCodedResponse::Success(RPCResponse::BlocksByRoot(Box::new(base_block()))),
        )
        .unwrap();

        let mut part = encoded_bytes.split_to(3);

        assert_eq!(
            decode(Protocol::BlocksByRange, Version::V2, &mut part),
            Ok(None)
        )
    }

    #[test]
    fn test_decode_malicious_status_message() {
        // 10 byte snappy stream identifier
        let stream_identifier: &'static [u8] = b"\xFF\x06\x00\x00sNaPpY";

        assert_eq!(stream_identifier.len(), 10);

        // byte 0(0xFE) is padding chunk type identifier for snappy messages
        // byte 1,2,3 are chunk length (little endian)
        let malicious_padding: &'static [u8] = b"\xFE\x00\x00\x00";

        // Status message is 84 bytes uncompressed. `max_compressed_len` is 32 + 84 + 84/6 = 130.
        let status_message_bytes = StatusMessage {
            fork_digest: [0; 4],
            finalized_root: Hash256::from_low_u64_be(0),
            finalized_epoch: Epoch::new(1),
            head_root: Hash256::from_low_u64_be(0),
            head_slot: Slot::new(1),
        }
        .as_ssz_bytes();

        assert_eq!(status_message_bytes.len(), 84);
        assert_eq!(snap::raw::max_compress_len(status_message_bytes.len()), 130);

        let mut uvi_codec: Uvi<usize> = Uvi::default();
        let mut dst = BytesMut::with_capacity(1024);

        // Insert length-prefix
        uvi_codec
            .encode(status_message_bytes.len(), &mut dst)
            .unwrap();

        // Insert snappy stream identifier
        dst.extend_from_slice(stream_identifier);

        // Insert malicious padding of 80 bytes.
        for _ in 0..20 {
            dst.extend_from_slice(malicious_padding);
        }

        // Insert payload (42 bytes compressed)
        let mut writer = FrameEncoder::new(Vec::new());
        writer.write_all(&status_message_bytes).unwrap();
        writer.flush().unwrap();
        assert_eq!(writer.get_ref().len(), 42);
        dst.extend_from_slice(writer.get_ref());

        // 10 (for stream identifier) + 80 + 42 = 132 > `max_compressed_len`. Hence, decoding should fail with `InvalidData`.
        assert_eq!(
            decode(Protocol::Status, Version::V1, &mut dst).unwrap_err(),
            RPCError::InvalidData
        );
    }

    #[test]
    fn test_decode_malicious_v2_message() {
        let fork_context = Arc::new(fork_context());

        // 10 byte snappy stream identifier
        let stream_identifier: &'static [u8] = b"\xFF\x06\x00\x00sNaPpY";

        assert_eq!(stream_identifier.len(), 10);

        // byte 0(0xFE) is padding chunk type identifier for snappy messages
        // byte 1,2,3 are chunk length (little endian)
        let malicious_padding: &'static [u8] = b"\xFE\x00\x00\x00";

        // Full altair block is 157980 bytes uncompressed. `max_compressed_len` is 32 + 157980 + 157980/6 = 184342.
        let block_message_bytes = altair_block().as_ssz_bytes();

        assert_eq!(block_message_bytes.len(), 157980);
        assert_eq!(
            snap::raw::max_compress_len(block_message_bytes.len()),
            184342
        );

        let mut uvi_codec: Uvi<usize> = Uvi::default();
        let mut dst = BytesMut::with_capacity(1024);

        // Insert context bytes
        dst.extend_from_slice(&fork_context.to_context_bytes(ForkName::Altair).unwrap());

        // Insert length-prefix
        uvi_codec
            .encode(block_message_bytes.len(), &mut dst)
            .unwrap();

        // Insert snappy stream identifier
        dst.extend_from_slice(stream_identifier);

        // Insert malicious padding of 176240 bytes.
        for _ in 0..44060 {
            dst.extend_from_slice(malicious_padding);
        }

        // Insert payload (8106 bytes compressed)
        let mut writer = FrameEncoder::new(Vec::new());
        writer.write_all(&block_message_bytes).unwrap();
        writer.flush().unwrap();
        assert_eq!(writer.get_ref().len(), 8106);
        dst.extend_from_slice(writer.get_ref());

        // 10 (for stream identifier) + 176240 + 8106 = 184356 > `max_compressed_len`. Hence, decoding should fail with `InvalidData`.
        assert_eq!(
            decode(Protocol::BlocksByRange, Version::V2, &mut dst).unwrap_err(),
            RPCError::InvalidData
        );
    }
}
