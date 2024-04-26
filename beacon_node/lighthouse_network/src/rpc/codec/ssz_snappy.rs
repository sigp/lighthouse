use crate::rpc::methods::*;
use crate::rpc::{
    codec::base::OutboundCodec,
    protocol::{Encoding, ProtocolId, RPCError, SupportedProtocol, ERROR_TYPE_MAX, ERROR_TYPE_MIN},
};
use crate::rpc::{InboundRequest, OutboundRequest};
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
    BlobSidecar, ChainSpec, EthSpec, ForkContext, ForkName, Hash256, LightClientBootstrap,
    LightClientFinalityUpdate, LightClientOptimisticUpdate, RuntimeVariableList, SignedBeaconBlock,
    SignedBeaconBlockAltair, SignedBeaconBlockBase, SignedBeaconBlockBellatrix,
    SignedBeaconBlockCapella, SignedBeaconBlockDeneb, SignedBeaconBlockElectra,
};
use unsigned_varint::codec::Uvi;

const CONTEXT_BYTES_LEN: usize = 4;

/* Inbound Codec */

pub struct SSZSnappyInboundCodec<E: EthSpec> {
    protocol: ProtocolId,
    inner: Uvi<usize>,
    len: Option<usize>,
    /// Maximum bytes that can be sent in one req/resp chunked responses.
    max_packet_size: usize,
    fork_context: Arc<ForkContext>,
    phantom: PhantomData<E>,
}

impl<E: EthSpec> SSZSnappyInboundCodec<E> {
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
impl<E: EthSpec> Encoder<RPCCodedResponse<E>> for SSZSnappyInboundCodec<E> {
    type Error = RPCError;

    fn encode(&mut self, item: RPCCodedResponse<E>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = match &item {
            RPCCodedResponse::Success(resp) => match &resp {
                RPCResponse::Status(res) => res.as_ssz_bytes(),
                RPCResponse::BlocksByRange(res) => res.as_ssz_bytes(),
                RPCResponse::BlocksByRoot(res) => res.as_ssz_bytes(),
                RPCResponse::BlobsByRange(res) => res.as_ssz_bytes(),
                RPCResponse::BlobsByRoot(res) => res.as_ssz_bytes(),
                RPCResponse::LightClientBootstrap(res) => res.as_ssz_bytes(),
                RPCResponse::LightClientOptimisticUpdate(res) => res.as_ssz_bytes(),
                RPCResponse::LightClientFinalityUpdate(res) => res.as_ssz_bytes(),
                RPCResponse::Pong(res) => res.data.as_ssz_bytes(),
                RPCResponse::MetaData(res) =>
                // Encode the correct version of the MetaData response based on the negotiated version.
                {
                    match self.protocol.versioned_protocol {
                        SupportedProtocol::MetaDataV1 => res.metadata_v1().as_ssz_bytes(),
                        // We always send V2 metadata responses from the behaviour
                        // No change required.
                        SupportedProtocol::MetaDataV2 => res.metadata_v2().as_ssz_bytes(),
                        _ => unreachable!(
                            "We only send metadata responses on negotiating metadata requests"
                        ),
                    }
                }
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

        // Add context bytes if required
        if let Some(ref context_bytes) = context_bytes(&self.protocol, &self.fork_context, &item) {
            dst.extend_from_slice(context_bytes);
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
impl<E: EthSpec> Decoder for SSZSnappyInboundCodec<E> {
    type Item = InboundRequest<E>;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if self.protocol.versioned_protocol == SupportedProtocol::MetaDataV1 {
            return Ok(Some(InboundRequest::MetaData(MetadataRequest::new_v1())));
        }
        if self.protocol.versioned_protocol == SupportedProtocol::MetaDataV2 {
            return Ok(Some(InboundRequest::MetaData(MetadataRequest::new_v2())));
        }
        let Some(length) = handle_length(&mut self.inner, &mut self.len, src)? else {
            return Ok(None);
        };

        // Should not attempt to decode rpc chunks with `length > max_packet_size` or not within bounds of
        // packet size for ssz container corresponding to `self.protocol`.
        let ssz_limits = self.protocol.rpc_request_limits(&self.fork_context.spec);
        if ssz_limits.is_out_of_bounds(length, self.max_packet_size) {
            return Err(RPCError::InvalidData(format!(
                "RPC request length for protocol {:?} is out of bounds, length {}",
                self.protocol.versioned_protocol, length
            )));
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
                handle_rpc_request(
                    self.protocol.versioned_protocol,
                    &decoded_buffer,
                    &self.fork_context.spec,
                )
            }
            Err(e) => handle_error(e, reader.get_ref().get_ref().position(), max_compressed_len),
        }
    }
}

/* Outbound Codec: Codec for initiating RPC requests */
pub struct SSZSnappyOutboundCodec<E: EthSpec> {
    inner: Uvi<usize>,
    len: Option<usize>,
    protocol: ProtocolId,
    /// Maximum bytes that can be sent in one req/resp chunked responses.
    max_packet_size: usize,
    /// The fork name corresponding to the received context bytes.
    fork_name: Option<ForkName>,
    fork_context: Arc<ForkContext>,
    phantom: PhantomData<E>,
}

impl<E: EthSpec> SSZSnappyOutboundCodec<E> {
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
impl<E: EthSpec> Encoder<OutboundRequest<E>> for SSZSnappyOutboundCodec<E> {
    type Error = RPCError;

    fn encode(&mut self, item: OutboundRequest<E>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = match item {
            OutboundRequest::Status(req) => req.as_ssz_bytes(),
            OutboundRequest::Goodbye(req) => req.as_ssz_bytes(),
            OutboundRequest::BlocksByRange(r) => match r {
                OldBlocksByRangeRequest::V1(req) => req.as_ssz_bytes(),
                OldBlocksByRangeRequest::V2(req) => req.as_ssz_bytes(),
            },
            OutboundRequest::BlocksByRoot(r) => match r {
                BlocksByRootRequest::V1(req) => req.block_roots.as_ssz_bytes(),
                BlocksByRootRequest::V2(req) => req.block_roots.as_ssz_bytes(),
            },
            OutboundRequest::BlobsByRange(req) => req.as_ssz_bytes(),
            OutboundRequest::BlobsByRoot(req) => req.blob_ids.as_ssz_bytes(),
            OutboundRequest::Ping(req) => req.as_ssz_bytes(),
            OutboundRequest::MetaData(_) => return Ok(()), // no metadata to encode
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
impl<E: EthSpec> Decoder for SSZSnappyOutboundCodec<E> {
    type Item = RPCResponse<E>;
    type Error = RPCError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Read the context bytes if required
        if self.protocol.has_context_bytes() && self.fork_name.is_none() {
            if src.len() >= CONTEXT_BYTES_LEN {
                let context_bytes = src.split_to(CONTEXT_BYTES_LEN);
                let mut result = [0; CONTEXT_BYTES_LEN];
                result.copy_from_slice(context_bytes.as_ref());
                self.fork_name = Some(context_bytes_to_fork_name(
                    result,
                    self.fork_context.clone(),
                )?);
            } else {
                return Ok(None);
            }
        }
        let Some(length) = handle_length(&mut self.inner, &mut self.len, src)? else {
            return Ok(None);
        };

        // Should not attempt to decode rpc chunks with `length > max_packet_size` or not within bounds of
        // packet size for ssz container corresponding to `self.protocol`.
        let ssz_limits = self.protocol.rpc_response_limits::<E>(&self.fork_context);
        if ssz_limits.is_out_of_bounds(length, self.max_packet_size) {
            return Err(RPCError::InvalidData(format!(
                "RPC response length is out of bounds, length {}, max {}, min {}",
                length, ssz_limits.max, ssz_limits.min
            )));
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
                // Safe to `take` from `self.fork_name` as we have all the bytes we need to
                // decode an ssz object at this point.
                let fork_name = self.fork_name.take();
                handle_rpc_response(self.protocol.versioned_protocol, &decoded_buffer, fork_name)
            }
            Err(e) => handle_error(e, reader.get_ref().get_ref().position(), max_compressed_len),
        }
    }
}

impl<E: EthSpec> OutboundCodec<OutboundRequest<E>> for SSZSnappyOutboundCodec<E> {
    type CodecErrorType = ErrorType;

    fn decode_error(
        &mut self,
        src: &mut BytesMut,
    ) -> Result<Option<Self::CodecErrorType>, RPCError> {
        let Some(length) = handle_length(&mut self.inner, &mut self.len, src)? else {
            return Ok(None);
        };

        // Should not attempt to decode rpc chunks with `length > max_packet_size` or not within bounds of
        // packet size for ssz container corresponding to `ErrorType`.
        if length > self.max_packet_size || length > *ERROR_TYPE_MAX || length < *ERROR_TYPE_MIN {
            return Err(RPCError::InvalidData(format!(
                "RPC Error length is out of bounds, length {}",
                length
            )));
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
                Err(RPCError::InvalidData(format!(
                    "Received malicious snappy message, num_bytes {}, max_compressed_len {}",
                    num_bytes, max_compressed_len
                )))
            } else {
                // Haven't received enough bytes to decode yet, wait for more
                Ok(None)
            }
        }
        _ => Err(RPCError::from(err)),
    }
}

/// Returns `Some(context_bytes)` for encoding RPC responses that require context bytes.
/// Returns `None` when context bytes are not required.
fn context_bytes<E: EthSpec>(
    protocol: &ProtocolId,
    fork_context: &ForkContext,
    resp: &RPCCodedResponse<E>,
) -> Option<[u8; CONTEXT_BYTES_LEN]> {
    // Add the context bytes if required
    if protocol.has_context_bytes() {
        if let RPCCodedResponse::Success(rpc_variant) = resp {
            match rpc_variant {
                RPCResponse::BlocksByRange(ref_box_block)
                | RPCResponse::BlocksByRoot(ref_box_block) => {
                    return match **ref_box_block {
                        // NOTE: If you are adding another fork type here, be sure to modify the
                        //       `fork_context.to_context_bytes()` function to support it as well!
                        SignedBeaconBlock::Electra { .. } => {
                            fork_context.to_context_bytes(ForkName::Electra)
                        }
                        SignedBeaconBlock::Deneb { .. } => {
                            fork_context.to_context_bytes(ForkName::Deneb)
                        }
                        SignedBeaconBlock::Capella { .. } => {
                            fork_context.to_context_bytes(ForkName::Capella)
                        }
                        SignedBeaconBlock::Bellatrix { .. } => {
                            fork_context.to_context_bytes(ForkName::Bellatrix)
                        }
                        SignedBeaconBlock::Altair { .. } => {
                            fork_context.to_context_bytes(ForkName::Altair)
                        }
                        SignedBeaconBlock::Base { .. } => {
                            Some(fork_context.genesis_context_bytes())
                        }
                    };
                }
                RPCResponse::BlobsByRange(_) | RPCResponse::BlobsByRoot(_) => {
                    return fork_context.to_context_bytes(ForkName::Deneb);
                }
                RPCResponse::LightClientBootstrap(lc_bootstrap) => {
                    return lc_bootstrap
                        .map_with_fork_name(|fork_name| fork_context.to_context_bytes(fork_name));
                }
                RPCResponse::LightClientOptimisticUpdate(lc_optimistic_update) => {
                    return lc_optimistic_update
                        .map_with_fork_name(|fork_name| fork_context.to_context_bytes(fork_name));
                }
                RPCResponse::LightClientFinalityUpdate(lc_finality_update) => {
                    return lc_finality_update
                        .map_with_fork_name(|fork_name| fork_context.to_context_bytes(fork_name));
                }
                // These will not pass the has_context_bytes() check
                RPCResponse::Status(_) | RPCResponse::Pong(_) | RPCResponse::MetaData(_) => {
                    return None;
                }
            }
        }
    }
    None
}

/// Decodes the length-prefix from the bytes as an unsigned protobuf varint.
///
/// Returns `Ok(Some(length))` by decoding the bytes if required.
/// Returns `Ok(None)` if more bytes are needed to decode the length-prefix.
/// Returns an `RPCError` for a decoding error.
fn handle_length(
    uvi_codec: &mut Uvi<usize>,
    len: &mut Option<usize>,
    bytes: &mut BytesMut,
) -> Result<Option<usize>, RPCError> {
    if let Some(length) = len {
        Ok(Some(*length))
    } else {
        // Decode the length of the uncompressed bytes from an unsigned varint
        // Note: length-prefix of > 10 bytes(uint64) would be a decoding error
        match uvi_codec.decode(bytes).map_err(RPCError::from)? {
            Some(length) => {
                *len = Some(length);
                Ok(Some(length))
            }
            None => Ok(None), // need more bytes to decode length
        }
    }
}

/// Decodes an `InboundRequest` from the byte stream.
/// `decoded_buffer` should be an ssz-encoded bytestream with
// length = length-prefix received in the beginning of the stream.
fn handle_rpc_request<E: EthSpec>(
    versioned_protocol: SupportedProtocol,
    decoded_buffer: &[u8],
    spec: &ChainSpec,
) -> Result<Option<InboundRequest<E>>, RPCError> {
    match versioned_protocol {
        SupportedProtocol::StatusV1 => Ok(Some(InboundRequest::Status(
            StatusMessage::from_ssz_bytes(decoded_buffer)?,
        ))),
        SupportedProtocol::GoodbyeV1 => Ok(Some(InboundRequest::Goodbye(
            GoodbyeReason::from_ssz_bytes(decoded_buffer)?,
        ))),
        SupportedProtocol::BlocksByRangeV2 => Ok(Some(InboundRequest::BlocksByRange(
            OldBlocksByRangeRequest::V2(OldBlocksByRangeRequestV2::from_ssz_bytes(decoded_buffer)?),
        ))),
        SupportedProtocol::BlocksByRangeV1 => Ok(Some(InboundRequest::BlocksByRange(
            OldBlocksByRangeRequest::V1(OldBlocksByRangeRequestV1::from_ssz_bytes(decoded_buffer)?),
        ))),
        SupportedProtocol::BlocksByRootV2 => Ok(Some(InboundRequest::BlocksByRoot(
            BlocksByRootRequest::V2(BlocksByRootRequestV2 {
                block_roots: RuntimeVariableList::from_ssz_bytes(
                    decoded_buffer,
                    spec.max_request_blocks as usize,
                )?,
            }),
        ))),
        SupportedProtocol::BlocksByRootV1 => Ok(Some(InboundRequest::BlocksByRoot(
            BlocksByRootRequest::V1(BlocksByRootRequestV1 {
                block_roots: RuntimeVariableList::from_ssz_bytes(
                    decoded_buffer,
                    spec.max_request_blocks as usize,
                )?,
            }),
        ))),
        SupportedProtocol::BlobsByRangeV1 => Ok(Some(InboundRequest::BlobsByRange(
            BlobsByRangeRequest::from_ssz_bytes(decoded_buffer)?,
        ))),
        SupportedProtocol::BlobsByRootV1 => {
            Ok(Some(InboundRequest::BlobsByRoot(BlobsByRootRequest {
                blob_ids: RuntimeVariableList::from_ssz_bytes(
                    decoded_buffer,
                    spec.max_request_blob_sidecars as usize,
                )?,
            })))
        }
        SupportedProtocol::PingV1 => Ok(Some(InboundRequest::Ping(Ping {
            data: u64::from_ssz_bytes(decoded_buffer)?,
        }))),
        SupportedProtocol::LightClientBootstrapV1 => Ok(Some(
            InboundRequest::LightClientBootstrap(LightClientBootstrapRequest {
                root: Hash256::from_ssz_bytes(decoded_buffer)?,
            }),
        )),
        SupportedProtocol::LightClientOptimisticUpdateV1 => {
            Ok(Some(InboundRequest::LightClientOptimisticUpdate))
        }
        SupportedProtocol::LightClientFinalityUpdateV1 => {
            Ok(Some(InboundRequest::LightClientFinalityUpdate))
        }
        // MetaData requests return early from InboundUpgrade and do not reach the decoder.
        // Handle this case just for completeness.
        SupportedProtocol::MetaDataV2 => {
            if !decoded_buffer.is_empty() {
                Err(RPCError::InternalError(
                    "Metadata requests shouldn't reach decoder",
                ))
            } else {
                Ok(Some(InboundRequest::MetaData(MetadataRequest::new_v2())))
            }
        }
        SupportedProtocol::MetaDataV1 => {
            if !decoded_buffer.is_empty() {
                Err(RPCError::InvalidData("Metadata request".to_string()))
            } else {
                Ok(Some(InboundRequest::MetaData(MetadataRequest::new_v1())))
            }
        }
    }
}

/// Decodes a `RPCResponse` from the byte stream.
/// `decoded_buffer` should be an ssz-encoded bytestream with
/// length = length-prefix received in the beginning of the stream.
///
/// For BlocksByRange/BlocksByRoot reponses, decodes the appropriate response
/// according to the received `ForkName`.
fn handle_rpc_response<E: EthSpec>(
    versioned_protocol: SupportedProtocol,
    decoded_buffer: &[u8],
    fork_name: Option<ForkName>,
) -> Result<Option<RPCResponse<E>>, RPCError> {
    match versioned_protocol {
        SupportedProtocol::StatusV1 => Ok(Some(RPCResponse::Status(
            StatusMessage::from_ssz_bytes(decoded_buffer)?,
        ))),
        // This case should be unreachable as `Goodbye` has no response.
        SupportedProtocol::GoodbyeV1 => Err(RPCError::InvalidData(
            "Goodbye RPC message has no valid response".to_string(),
        )),
        SupportedProtocol::BlocksByRangeV1 => Ok(Some(RPCResponse::BlocksByRange(Arc::new(
            SignedBeaconBlock::Base(SignedBeaconBlockBase::from_ssz_bytes(decoded_buffer)?),
        )))),
        SupportedProtocol::BlocksByRootV1 => Ok(Some(RPCResponse::BlocksByRoot(Arc::new(
            SignedBeaconBlock::Base(SignedBeaconBlockBase::from_ssz_bytes(decoded_buffer)?),
        )))),
        SupportedProtocol::BlobsByRangeV1 => match fork_name {
            Some(ForkName::Deneb) => Ok(Some(RPCResponse::BlobsByRange(Arc::new(
                BlobSidecar::from_ssz_bytes(decoded_buffer)?,
            )))),
            Some(_) => Err(RPCError::ErrorResponse(
                RPCResponseErrorCode::InvalidRequest,
                "Invalid fork name for blobs by range".to_string(),
            )),
            None => Err(RPCError::ErrorResponse(
                RPCResponseErrorCode::InvalidRequest,
                format!(
                    "No context bytes provided for {:?} response",
                    versioned_protocol
                ),
            )),
        },
        SupportedProtocol::BlobsByRootV1 => match fork_name {
            Some(ForkName::Deneb) => Ok(Some(RPCResponse::BlobsByRoot(Arc::new(
                BlobSidecar::from_ssz_bytes(decoded_buffer)?,
            )))),
            Some(_) => Err(RPCError::ErrorResponse(
                RPCResponseErrorCode::InvalidRequest,
                "Invalid fork name for blobs by root".to_string(),
            )),
            None => Err(RPCError::ErrorResponse(
                RPCResponseErrorCode::InvalidRequest,
                format!(
                    "No context bytes provided for {:?} response",
                    versioned_protocol
                ),
            )),
        },
        SupportedProtocol::PingV1 => Ok(Some(RPCResponse::Pong(Ping {
            data: u64::from_ssz_bytes(decoded_buffer)?,
        }))),
        SupportedProtocol::MetaDataV1 => Ok(Some(RPCResponse::MetaData(MetaData::V1(
            MetaDataV1::from_ssz_bytes(decoded_buffer)?,
        )))),
        SupportedProtocol::LightClientBootstrapV1 => match fork_name {
            Some(fork_name) => Ok(Some(RPCResponse::LightClientBootstrap(Arc::new(
                LightClientBootstrap::from_ssz_bytes(decoded_buffer, fork_name)?,
            )))),
            None => Err(RPCError::ErrorResponse(
                RPCResponseErrorCode::InvalidRequest,
                format!(
                    "No context bytes provided for {:?} response",
                    versioned_protocol
                ),
            )),
        },
        SupportedProtocol::LightClientOptimisticUpdateV1 => match fork_name {
            Some(fork_name) => Ok(Some(RPCResponse::LightClientOptimisticUpdate(Arc::new(
                LightClientOptimisticUpdate::from_ssz_bytes(decoded_buffer, fork_name)?,
            )))),
            None => Err(RPCError::ErrorResponse(
                RPCResponseErrorCode::InvalidRequest,
                format!(
                    "No context bytes provided for {:?} response",
                    versioned_protocol
                ),
            )),
        },
        SupportedProtocol::LightClientFinalityUpdateV1 => match fork_name {
            Some(fork_name) => Ok(Some(RPCResponse::LightClientFinalityUpdate(Arc::new(
                LightClientFinalityUpdate::from_ssz_bytes(decoded_buffer, fork_name)?,
            )))),
            None => Err(RPCError::ErrorResponse(
                RPCResponseErrorCode::InvalidRequest,
                format!(
                    "No context bytes provided for {:?} response",
                    versioned_protocol
                ),
            )),
        },
        // MetaData V2 responses have no context bytes, so behave similarly to V1 responses
        SupportedProtocol::MetaDataV2 => Ok(Some(RPCResponse::MetaData(MetaData::V2(
            MetaDataV2::from_ssz_bytes(decoded_buffer)?,
        )))),
        SupportedProtocol::BlocksByRangeV2 => match fork_name {
            Some(ForkName::Altair) => Ok(Some(RPCResponse::BlocksByRange(Arc::new(
                SignedBeaconBlock::Altair(SignedBeaconBlockAltair::from_ssz_bytes(decoded_buffer)?),
            )))),

            Some(ForkName::Base) => Ok(Some(RPCResponse::BlocksByRange(Arc::new(
                SignedBeaconBlock::Base(SignedBeaconBlockBase::from_ssz_bytes(decoded_buffer)?),
            )))),
            Some(ForkName::Bellatrix) => Ok(Some(RPCResponse::BlocksByRange(Arc::new(
                SignedBeaconBlock::Bellatrix(SignedBeaconBlockBellatrix::from_ssz_bytes(
                    decoded_buffer,
                )?),
            )))),
            Some(ForkName::Capella) => Ok(Some(RPCResponse::BlocksByRange(Arc::new(
                SignedBeaconBlock::Capella(SignedBeaconBlockCapella::from_ssz_bytes(
                    decoded_buffer,
                )?),
            )))),
            Some(ForkName::Deneb) => Ok(Some(RPCResponse::BlocksByRange(Arc::new(
                SignedBeaconBlock::Deneb(SignedBeaconBlockDeneb::from_ssz_bytes(decoded_buffer)?),
            )))),
            Some(ForkName::Electra) => Ok(Some(RPCResponse::BlocksByRange(Arc::new(
                SignedBeaconBlock::Electra(SignedBeaconBlockElectra::from_ssz_bytes(
                    decoded_buffer,
                )?),
            )))),
            None => Err(RPCError::ErrorResponse(
                RPCResponseErrorCode::InvalidRequest,
                format!(
                    "No context bytes provided for {:?} response",
                    versioned_protocol
                ),
            )),
        },
        SupportedProtocol::BlocksByRootV2 => match fork_name {
            Some(ForkName::Altair) => Ok(Some(RPCResponse::BlocksByRoot(Arc::new(
                SignedBeaconBlock::Altair(SignedBeaconBlockAltair::from_ssz_bytes(decoded_buffer)?),
            )))),
            Some(ForkName::Base) => Ok(Some(RPCResponse::BlocksByRoot(Arc::new(
                SignedBeaconBlock::Base(SignedBeaconBlockBase::from_ssz_bytes(decoded_buffer)?),
            )))),
            Some(ForkName::Bellatrix) => Ok(Some(RPCResponse::BlocksByRoot(Arc::new(
                SignedBeaconBlock::Bellatrix(SignedBeaconBlockBellatrix::from_ssz_bytes(
                    decoded_buffer,
                )?),
            )))),
            Some(ForkName::Capella) => Ok(Some(RPCResponse::BlocksByRoot(Arc::new(
                SignedBeaconBlock::Capella(SignedBeaconBlockCapella::from_ssz_bytes(
                    decoded_buffer,
                )?),
            )))),
            Some(ForkName::Deneb) => Ok(Some(RPCResponse::BlocksByRoot(Arc::new(
                SignedBeaconBlock::Deneb(SignedBeaconBlockDeneb::from_ssz_bytes(decoded_buffer)?),
            )))),
            Some(ForkName::Electra) => Ok(Some(RPCResponse::BlocksByRoot(Arc::new(
                SignedBeaconBlock::Electra(SignedBeaconBlockElectra::from_ssz_bytes(
                    decoded_buffer,
                )?),
            )))),
            None => Err(RPCError::ErrorResponse(
                RPCResponseErrorCode::InvalidRequest,
                format!(
                    "No context bytes provided for {:?} response",
                    versioned_protocol
                ),
            )),
        },
    }
}

/// Takes the context bytes and a fork_context and returns the corresponding fork_name.
fn context_bytes_to_fork_name(
    context_bytes: [u8; CONTEXT_BYTES_LEN],
    fork_context: Arc<ForkContext>,
) -> Result<ForkName, RPCError> {
    fork_context
        .from_context_bytes(context_bytes)
        .cloned()
        .ok_or_else(|| {
            let encoded = hex::encode(context_bytes);
            RPCError::ErrorResponse(
                RPCResponseErrorCode::InvalidRequest,
                format!(
                    "Context bytes {} do not correspond to a valid fork",
                    encoded
                ),
            )
        })
}
#[cfg(test)]
mod tests {

    use super::*;
    use crate::rpc::protocol::*;
    use crate::types::{EnrAttestationBitfield, EnrSyncCommitteeBitfield};
    use types::{
        blob_sidecar::BlobIdentifier, BeaconBlock, BeaconBlockAltair, BeaconBlockBase,
        BeaconBlockBellatrix, EmptyBlock, Epoch, FullPayload, Signature, Slot,
    };

    type Spec = types::MainnetEthSpec;

    fn fork_context(fork_name: ForkName) -> ForkContext {
        let mut chain_spec = Spec::default_spec();
        let altair_fork_epoch = Epoch::new(1);
        let bellatrix_fork_epoch = Epoch::new(2);
        let capella_fork_epoch = Epoch::new(3);
        let deneb_fork_epoch = Epoch::new(4);
        let electra_fork_epoch = Epoch::new(5);

        chain_spec.altair_fork_epoch = Some(altair_fork_epoch);
        chain_spec.bellatrix_fork_epoch = Some(bellatrix_fork_epoch);
        chain_spec.capella_fork_epoch = Some(capella_fork_epoch);
        chain_spec.deneb_fork_epoch = Some(deneb_fork_epoch);
        chain_spec.electra_fork_epoch = Some(electra_fork_epoch);

        let current_slot = match fork_name {
            ForkName::Base => Slot::new(0),
            ForkName::Altair => altair_fork_epoch.start_slot(Spec::slots_per_epoch()),
            ForkName::Bellatrix => bellatrix_fork_epoch.start_slot(Spec::slots_per_epoch()),
            ForkName::Capella => capella_fork_epoch.start_slot(Spec::slots_per_epoch()),
            ForkName::Deneb => deneb_fork_epoch.start_slot(Spec::slots_per_epoch()),
            ForkName::Electra => electra_fork_epoch.start_slot(Spec::slots_per_epoch()),
        };
        ForkContext::new::<Spec>(current_slot, Hash256::zero(), &chain_spec)
    }

    /// Smallest sized block across all current forks. Useful for testing
    /// min length check conditions.
    fn empty_base_block() -> SignedBeaconBlock<Spec> {
        let empty_block = BeaconBlock::Base(BeaconBlockBase::<Spec>::empty(&Spec::default_spec()));
        SignedBeaconBlock::from_block(empty_block, Signature::empty())
    }

    fn altair_block() -> SignedBeaconBlock<Spec> {
        let full_block =
            BeaconBlock::Altair(BeaconBlockAltair::<Spec>::full(&Spec::default_spec()));
        SignedBeaconBlock::from_block(full_block, Signature::empty())
    }

    fn empty_blob_sidecar() -> Arc<BlobSidecar<Spec>> {
        Arc::new(BlobSidecar::empty())
    }

    /// Bellatrix block with length < max_rpc_size.
    fn bellatrix_block_small(
        fork_context: &ForkContext,
        spec: &ChainSpec,
    ) -> SignedBeaconBlock<Spec> {
        let mut block: BeaconBlockBellatrix<_, FullPayload<Spec>> =
            BeaconBlockBellatrix::empty(&Spec::default_spec());
        let tx = VariableList::from(vec![0; 1024]);
        let txs = VariableList::from(std::iter::repeat(tx).take(5000).collect::<Vec<_>>());

        block.body.execution_payload.execution_payload.transactions = txs;

        let block = BeaconBlock::Bellatrix(block);
        assert!(block.ssz_bytes_len() <= max_rpc_size(fork_context, spec.max_chunk_size as usize));
        SignedBeaconBlock::from_block(block, Signature::empty())
    }

    /// Bellatrix block with length > MAX_RPC_SIZE.
    /// The max limit for a Bellatrix block is in the order of ~16GiB which wouldn't fit in memory.
    /// Hence, we generate a Bellatrix block just greater than `MAX_RPC_SIZE` to test rejection on the rpc layer.
    fn bellatrix_block_large(
        fork_context: &ForkContext,
        spec: &ChainSpec,
    ) -> SignedBeaconBlock<Spec> {
        let mut block: BeaconBlockBellatrix<_, FullPayload<Spec>> =
            BeaconBlockBellatrix::empty(&Spec::default_spec());
        let tx = VariableList::from(vec![0; 1024]);
        let txs = VariableList::from(std::iter::repeat(tx).take(100000).collect::<Vec<_>>());

        block.body.execution_payload.execution_payload.transactions = txs;

        let block = BeaconBlock::Bellatrix(block);
        assert!(block.ssz_bytes_len() > max_rpc_size(fork_context, spec.max_chunk_size as usize));
        SignedBeaconBlock::from_block(block, Signature::empty())
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

    fn bbrange_request_v1() -> OldBlocksByRangeRequest {
        OldBlocksByRangeRequest::new_v1(0, 10, 1)
    }

    fn bbrange_request_v2() -> OldBlocksByRangeRequest {
        OldBlocksByRangeRequest::new(0, 10, 1)
    }

    fn blbrange_request() -> BlobsByRangeRequest {
        BlobsByRangeRequest {
            start_slot: 0,
            count: 10,
        }
    }

    fn bbroot_request_v1(spec: &ChainSpec) -> BlocksByRootRequest {
        BlocksByRootRequest::new_v1(vec![Hash256::zero()], spec)
    }

    fn bbroot_request_v2(spec: &ChainSpec) -> BlocksByRootRequest {
        BlocksByRootRequest::new(vec![Hash256::zero()], spec)
    }

    fn blbroot_request(spec: &ChainSpec) -> BlobsByRootRequest {
        BlobsByRootRequest::new(
            vec![BlobIdentifier {
                block_root: Hash256::zero(),
                index: 0,
            }],
            spec,
        )
    }

    fn ping_message() -> Ping {
        Ping { data: 1 }
    }

    fn metadata() -> MetaData<Spec> {
        MetaData::V1(MetaDataV1 {
            seq_number: 1,
            attnets: EnrAttestationBitfield::<Spec>::default(),
        })
    }

    fn metadata_v2() -> MetaData<Spec> {
        MetaData::V2(MetaDataV2 {
            seq_number: 1,
            attnets: EnrAttestationBitfield::<Spec>::default(),
            syncnets: EnrSyncCommitteeBitfield::<Spec>::default(),
        })
    }

    /// Encodes the given protocol response as bytes.
    fn encode_response(
        protocol: SupportedProtocol,
        message: RPCCodedResponse<Spec>,
        fork_name: ForkName,
        spec: &ChainSpec,
    ) -> Result<BytesMut, RPCError> {
        let snappy_protocol_id = ProtocolId::new(protocol, Encoding::SSZSnappy);
        let fork_context = Arc::new(fork_context(fork_name));
        let max_packet_size = max_rpc_size(&fork_context, spec.max_chunk_size as usize);

        let mut buf = BytesMut::new();
        let mut snappy_inbound_codec =
            SSZSnappyInboundCodec::<Spec>::new(snappy_protocol_id, max_packet_size, fork_context);

        snappy_inbound_codec.encode(message, &mut buf)?;
        Ok(buf)
    }

    fn encode_without_length_checks(
        bytes: Vec<u8>,
        fork_name: ForkName,
    ) -> Result<BytesMut, RPCError> {
        let fork_context = fork_context(fork_name);
        let mut dst = BytesMut::new();

        // Add context bytes if required
        dst.extend_from_slice(&fork_context.to_context_bytes(fork_name).unwrap());

        let mut uvi_codec: Uvi<usize> = Uvi::default();

        // Inserts the length prefix of the uncompressed bytes into dst
        // encoded as a unsigned varint
        uvi_codec
            .encode(bytes.len(), &mut dst)
            .map_err(RPCError::from)?;

        let mut writer = FrameEncoder::new(Vec::new());
        writer.write_all(&bytes).map_err(RPCError::from)?;
        writer.flush().map_err(RPCError::from)?;

        // Write compressed bytes to `dst`
        dst.extend_from_slice(writer.get_ref());

        Ok(dst)
    }

    /// Attempts to decode the given protocol bytes as an rpc response
    fn decode_response(
        protocol: SupportedProtocol,
        message: &mut BytesMut,
        fork_name: ForkName,
        spec: &ChainSpec,
    ) -> Result<Option<RPCResponse<Spec>>, RPCError> {
        let snappy_protocol_id = ProtocolId::new(protocol, Encoding::SSZSnappy);
        let fork_context = Arc::new(fork_context(fork_name));
        let max_packet_size = max_rpc_size(&fork_context, spec.max_chunk_size as usize);
        let mut snappy_outbound_codec =
            SSZSnappyOutboundCodec::<Spec>::new(snappy_protocol_id, max_packet_size, fork_context);
        // decode message just as snappy message
        snappy_outbound_codec.decode(message)
    }

    /// Encodes the provided protocol message as bytes and tries to decode the encoding bytes.
    fn encode_then_decode_response(
        protocol: SupportedProtocol,
        message: RPCCodedResponse<Spec>,
        fork_name: ForkName,
        spec: &ChainSpec,
    ) -> Result<Option<RPCResponse<Spec>>, RPCError> {
        let mut encoded = encode_response(protocol, message, fork_name, spec)?;
        decode_response(protocol, &mut encoded, fork_name, spec)
    }

    /// Verifies that requests we send are encoded in a way that we would correctly decode too.
    fn encode_then_decode_request(
        req: OutboundRequest<Spec>,
        fork_name: ForkName,
        spec: &ChainSpec,
    ) {
        let fork_context = Arc::new(fork_context(fork_name));
        let max_packet_size = max_rpc_size(&fork_context, spec.max_chunk_size as usize);
        let protocol = ProtocolId::new(req.versioned_protocol(), Encoding::SSZSnappy);
        // Encode a request we send
        let mut buf = BytesMut::new();
        let mut outbound_codec = SSZSnappyOutboundCodec::<Spec>::new(
            protocol.clone(),
            max_packet_size,
            fork_context.clone(),
        );
        outbound_codec.encode(req.clone(), &mut buf).unwrap();

        let mut inbound_codec =
            SSZSnappyInboundCodec::<Spec>::new(protocol.clone(), max_packet_size, fork_context);

        let decoded = inbound_codec.decode(&mut buf).unwrap().unwrap_or_else(|| {
            panic!(
                "Should correctly decode the request {} over protocol {:?} and fork {}",
                req, protocol, fork_name
            )
        });
        match req {
            OutboundRequest::Status(status) => {
                assert_eq!(decoded, InboundRequest::Status(status))
            }
            OutboundRequest::Goodbye(goodbye) => {
                assert_eq!(decoded, InboundRequest::Goodbye(goodbye))
            }
            OutboundRequest::BlocksByRange(bbrange) => {
                assert_eq!(decoded, InboundRequest::BlocksByRange(bbrange))
            }
            OutboundRequest::BlocksByRoot(bbroot) => {
                assert_eq!(decoded, InboundRequest::BlocksByRoot(bbroot))
            }
            OutboundRequest::BlobsByRange(blbrange) => {
                assert_eq!(decoded, InboundRequest::BlobsByRange(blbrange))
            }
            OutboundRequest::BlobsByRoot(bbroot) => {
                assert_eq!(decoded, InboundRequest::BlobsByRoot(bbroot))
            }
            OutboundRequest::Ping(ping) => {
                assert_eq!(decoded, InboundRequest::Ping(ping))
            }
            OutboundRequest::MetaData(metadata) => {
                assert_eq!(decoded, InboundRequest::MetaData(metadata))
            }
        }
    }

    // Test RPCResponse encoding/decoding for V1 messages
    #[test]
    fn test_encode_then_decode_v1() {
        let chain_spec = Spec::default_spec();

        assert_eq!(
            encode_then_decode_response(
                SupportedProtocol::StatusV1,
                RPCCodedResponse::Success(RPCResponse::Status(status_message())),
                ForkName::Base,
                &chain_spec,
            ),
            Ok(Some(RPCResponse::Status(status_message())))
        );

        assert_eq!(
            encode_then_decode_response(
                SupportedProtocol::PingV1,
                RPCCodedResponse::Success(RPCResponse::Pong(ping_message())),
                ForkName::Base,
                &chain_spec,
            ),
            Ok(Some(RPCResponse::Pong(ping_message())))
        );

        assert_eq!(
            encode_then_decode_response(
                SupportedProtocol::BlocksByRangeV1,
                RPCCodedResponse::Success(RPCResponse::BlocksByRange(Arc::new(empty_base_block()))),
                ForkName::Base,
                &chain_spec,
            ),
            Ok(Some(RPCResponse::BlocksByRange(Arc::new(
                empty_base_block()
            ))))
        );

        assert!(
            matches!(
                encode_then_decode_response(
                    SupportedProtocol::BlocksByRangeV1,
                    RPCCodedResponse::Success(RPCResponse::BlocksByRange(Arc::new(altair_block()))),
                    ForkName::Altair,
                    &chain_spec,
                )
                .unwrap_err(),
                RPCError::SSZDecodeError(_)
            ),
            "altair block cannot be decoded with blocks by range V1 version"
        );

        assert_eq!(
            encode_then_decode_response(
                SupportedProtocol::BlocksByRootV1,
                RPCCodedResponse::Success(RPCResponse::BlocksByRoot(Arc::new(empty_base_block()))),
                ForkName::Base,
                &chain_spec,
            ),
            Ok(Some(RPCResponse::BlocksByRoot(
                Arc::new(empty_base_block())
            )))
        );

        assert!(
            matches!(
                encode_then_decode_response(
                    SupportedProtocol::BlocksByRootV1,
                    RPCCodedResponse::Success(RPCResponse::BlocksByRoot(Arc::new(altair_block()))),
                    ForkName::Altair,
                    &chain_spec,
                )
                .unwrap_err(),
                RPCError::SSZDecodeError(_)
            ),
            "altair block cannot be decoded with blocks by range V1 version"
        );

        assert_eq!(
            encode_then_decode_response(
                SupportedProtocol::MetaDataV1,
                RPCCodedResponse::Success(RPCResponse::MetaData(metadata())),
                ForkName::Base,
                &chain_spec,
            ),
            Ok(Some(RPCResponse::MetaData(metadata()))),
        );

        // A MetaDataV2 still encodes as a MetaDataV1 since version is Version::V1
        assert_eq!(
            encode_then_decode_response(
                SupportedProtocol::MetaDataV1,
                RPCCodedResponse::Success(RPCResponse::MetaData(metadata_v2())),
                ForkName::Base,
                &chain_spec,
            ),
            Ok(Some(RPCResponse::MetaData(metadata()))),
        );

        assert_eq!(
            encode_then_decode_response(
                SupportedProtocol::BlobsByRangeV1,
                RPCCodedResponse::Success(RPCResponse::BlobsByRange(empty_blob_sidecar())),
                ForkName::Deneb,
                &chain_spec
            ),
            Ok(Some(RPCResponse::BlobsByRange(empty_blob_sidecar()))),
        );

        assert_eq!(
            encode_then_decode_response(
                SupportedProtocol::BlobsByRootV1,
                RPCCodedResponse::Success(RPCResponse::BlobsByRoot(empty_blob_sidecar())),
                ForkName::Deneb,
                &chain_spec
            ),
            Ok(Some(RPCResponse::BlobsByRoot(empty_blob_sidecar()))),
        );
    }

    // Test RPCResponse encoding/decoding for V1 messages
    #[test]
    fn test_encode_then_decode_v2() {
        let chain_spec = Spec::default_spec();

        assert_eq!(
            encode_then_decode_response(
                SupportedProtocol::BlocksByRangeV2,
                RPCCodedResponse::Success(RPCResponse::BlocksByRange(Arc::new(empty_base_block()))),
                ForkName::Base,
                &chain_spec,
            ),
            Ok(Some(RPCResponse::BlocksByRange(Arc::new(
                empty_base_block()
            ))))
        );

        // Decode the smallest possible base block when current fork is altair
        // This is useful for checking that we allow for blocks smaller than
        // the current_fork's rpc limit
        assert_eq!(
            encode_then_decode_response(
                SupportedProtocol::BlocksByRangeV2,
                RPCCodedResponse::Success(RPCResponse::BlocksByRange(Arc::new(empty_base_block()))),
                ForkName::Altair,
                &chain_spec,
            ),
            Ok(Some(RPCResponse::BlocksByRange(Arc::new(
                empty_base_block()
            ))))
        );

        assert_eq!(
            encode_then_decode_response(
                SupportedProtocol::BlocksByRangeV2,
                RPCCodedResponse::Success(RPCResponse::BlocksByRange(Arc::new(altair_block()))),
                ForkName::Altair,
                &chain_spec,
            ),
            Ok(Some(RPCResponse::BlocksByRange(Arc::new(altair_block()))))
        );

        let bellatrix_block_small =
            bellatrix_block_small(&fork_context(ForkName::Bellatrix), &chain_spec);
        let bellatrix_block_large =
            bellatrix_block_large(&fork_context(ForkName::Bellatrix), &chain_spec);

        assert_eq!(
            encode_then_decode_response(
                SupportedProtocol::BlocksByRangeV2,
                RPCCodedResponse::Success(RPCResponse::BlocksByRange(Arc::new(
                    bellatrix_block_small.clone()
                ))),
                ForkName::Bellatrix,
                &chain_spec,
            ),
            Ok(Some(RPCResponse::BlocksByRange(Arc::new(
                bellatrix_block_small.clone()
            ))))
        );

        let mut encoded =
            encode_without_length_checks(bellatrix_block_large.as_ssz_bytes(), ForkName::Bellatrix)
                .unwrap();

        assert!(
            matches!(
                decode_response(
                    SupportedProtocol::BlocksByRangeV2,
                    &mut encoded,
                    ForkName::Bellatrix,
                    &chain_spec,
                )
                .unwrap_err(),
                RPCError::InvalidData(_)
            ),
            "Decoding a block larger than max_rpc_size should fail"
        );

        assert_eq!(
            encode_then_decode_response(
                SupportedProtocol::BlocksByRootV2,
                RPCCodedResponse::Success(RPCResponse::BlocksByRoot(Arc::new(empty_base_block()))),
                ForkName::Base,
                &chain_spec,
            ),
            Ok(Some(RPCResponse::BlocksByRoot(
                Arc::new(empty_base_block())
            ))),
        );

        // Decode the smallest possible base block when current fork is altair
        // This is useful for checking that we allow for blocks smaller than
        // the current_fork's rpc limit
        assert_eq!(
            encode_then_decode_response(
                SupportedProtocol::BlocksByRootV2,
                RPCCodedResponse::Success(RPCResponse::BlocksByRoot(Arc::new(empty_base_block()))),
                ForkName::Altair,
                &chain_spec,
            ),
            Ok(Some(RPCResponse::BlocksByRoot(
                Arc::new(empty_base_block())
            )))
        );

        assert_eq!(
            encode_then_decode_response(
                SupportedProtocol::BlocksByRootV2,
                RPCCodedResponse::Success(RPCResponse::BlocksByRoot(Arc::new(altair_block()))),
                ForkName::Altair,
                &chain_spec,
            ),
            Ok(Some(RPCResponse::BlocksByRoot(Arc::new(altair_block()))))
        );

        assert_eq!(
            encode_then_decode_response(
                SupportedProtocol::BlocksByRootV2,
                RPCCodedResponse::Success(RPCResponse::BlocksByRoot(Arc::new(
                    bellatrix_block_small.clone()
                ))),
                ForkName::Bellatrix,
                &chain_spec,
            ),
            Ok(Some(RPCResponse::BlocksByRoot(Arc::new(
                bellatrix_block_small
            ))))
        );

        let mut encoded =
            encode_without_length_checks(bellatrix_block_large.as_ssz_bytes(), ForkName::Bellatrix)
                .unwrap();

        assert!(
            matches!(
                decode_response(
                    SupportedProtocol::BlocksByRootV2,
                    &mut encoded,
                    ForkName::Bellatrix,
                    &chain_spec,
                )
                .unwrap_err(),
                RPCError::InvalidData(_)
            ),
            "Decoding a block larger than max_rpc_size should fail"
        );

        // A MetaDataV1 still encodes as a MetaDataV2 since version is Version::V2
        assert_eq!(
            encode_then_decode_response(
                SupportedProtocol::MetaDataV2,
                RPCCodedResponse::Success(RPCResponse::MetaData(metadata())),
                ForkName::Base,
                &chain_spec,
            ),
            Ok(Some(RPCResponse::MetaData(metadata_v2())))
        );

        assert_eq!(
            encode_then_decode_response(
                SupportedProtocol::MetaDataV2,
                RPCCodedResponse::Success(RPCResponse::MetaData(metadata_v2())),
                ForkName::Altair,
                &chain_spec,
            ),
            Ok(Some(RPCResponse::MetaData(metadata_v2())))
        );
    }

    // Test RPCResponse encoding/decoding for V2 messages
    #[test]
    fn test_context_bytes_v2() {
        let fork_context = fork_context(ForkName::Altair);

        let chain_spec = Spec::default_spec();

        // Removing context bytes for v2 messages should error
        let mut encoded_bytes = encode_response(
            SupportedProtocol::BlocksByRangeV2,
            RPCCodedResponse::Success(RPCResponse::BlocksByRange(Arc::new(empty_base_block()))),
            ForkName::Base,
            &chain_spec,
        )
        .unwrap();

        let _ = encoded_bytes.split_to(4);

        assert!(matches!(
            decode_response(
                SupportedProtocol::BlocksByRangeV2,
                &mut encoded_bytes,
                ForkName::Base,
                &chain_spec,
            )
            .unwrap_err(),
            RPCError::ErrorResponse(RPCResponseErrorCode::InvalidRequest, _),
        ));

        let mut encoded_bytes = encode_response(
            SupportedProtocol::BlocksByRootV2,
            RPCCodedResponse::Success(RPCResponse::BlocksByRoot(Arc::new(empty_base_block()))),
            ForkName::Base,
            &chain_spec,
        )
        .unwrap();

        let _ = encoded_bytes.split_to(4);

        assert!(matches!(
            decode_response(
                SupportedProtocol::BlocksByRangeV2,
                &mut encoded_bytes,
                ForkName::Base,
                &chain_spec,
            )
            .unwrap_err(),
            RPCError::ErrorResponse(RPCResponseErrorCode::InvalidRequest, _),
        ));

        // Trying to decode a base block with altair context bytes should give ssz decoding error
        let mut encoded_bytes = encode_response(
            SupportedProtocol::BlocksByRangeV2,
            RPCCodedResponse::Success(RPCResponse::BlocksByRange(Arc::new(empty_base_block()))),
            ForkName::Altair,
            &chain_spec,
        )
        .unwrap();

        let mut wrong_fork_bytes = BytesMut::new();
        wrong_fork_bytes
            .extend_from_slice(&fork_context.to_context_bytes(ForkName::Altair).unwrap());
        wrong_fork_bytes.extend_from_slice(&encoded_bytes.split_off(4));

        assert!(matches!(
            decode_response(
                SupportedProtocol::BlocksByRangeV2,
                &mut wrong_fork_bytes,
                ForkName::Altair,
                &chain_spec,
            )
            .unwrap_err(),
            RPCError::SSZDecodeError(_),
        ));

        // Trying to decode an altair block with base context bytes should give ssz decoding error
        let mut encoded_bytes = encode_response(
            SupportedProtocol::BlocksByRootV2,
            RPCCodedResponse::Success(RPCResponse::BlocksByRoot(Arc::new(altair_block()))),
            ForkName::Altair,
            &chain_spec,
        )
        .unwrap();

        let mut wrong_fork_bytes = BytesMut::new();
        wrong_fork_bytes.extend_from_slice(&fork_context.to_context_bytes(ForkName::Base).unwrap());
        wrong_fork_bytes.extend_from_slice(&encoded_bytes.split_off(4));

        assert!(matches!(
            decode_response(
                SupportedProtocol::BlocksByRangeV2,
                &mut wrong_fork_bytes,
                ForkName::Altair,
                &chain_spec,
            )
            .unwrap_err(),
            RPCError::SSZDecodeError(_),
        ));

        // Adding context bytes to Protocols that don't require it should return an error
        let mut encoded_bytes = BytesMut::new();
        encoded_bytes.extend_from_slice(&fork_context.to_context_bytes(ForkName::Altair).unwrap());
        encoded_bytes.extend_from_slice(
            &encode_response(
                SupportedProtocol::MetaDataV2,
                RPCCodedResponse::Success(RPCResponse::MetaData(metadata())),
                ForkName::Altair,
                &chain_spec,
            )
            .unwrap(),
        );

        assert!(decode_response(
            SupportedProtocol::MetaDataV2,
            &mut encoded_bytes,
            ForkName::Altair,
            &chain_spec,
        )
        .is_err());

        // Sending context bytes which do not correspond to any fork should return an error
        let mut encoded_bytes = encode_response(
            SupportedProtocol::BlocksByRootV2,
            RPCCodedResponse::Success(RPCResponse::BlocksByRoot(Arc::new(empty_base_block()))),
            ForkName::Altair,
            &chain_spec,
        )
        .unwrap();

        let mut wrong_fork_bytes = BytesMut::new();
        wrong_fork_bytes.extend_from_slice(&[42, 42, 42, 42]);
        wrong_fork_bytes.extend_from_slice(&encoded_bytes.split_off(4));

        assert!(matches!(
            decode_response(
                SupportedProtocol::BlocksByRangeV2,
                &mut wrong_fork_bytes,
                ForkName::Altair,
                &chain_spec,
            )
            .unwrap_err(),
            RPCError::ErrorResponse(RPCResponseErrorCode::InvalidRequest, _),
        ));

        // Sending bytes less than context bytes length should wait for more bytes by returning `Ok(None)`
        let mut encoded_bytes = encode_response(
            SupportedProtocol::BlocksByRootV2,
            RPCCodedResponse::Success(RPCResponse::BlocksByRoot(Arc::new(empty_base_block()))),
            ForkName::Altair,
            &chain_spec,
        )
        .unwrap();

        let mut part = encoded_bytes.split_to(3);

        assert_eq!(
            decode_response(
                SupportedProtocol::BlocksByRangeV2,
                &mut part,
                ForkName::Altair,
                &chain_spec,
            ),
            Ok(None)
        )
    }

    #[test]
    fn test_encode_then_decode_request() {
        let chain_spec = Spec::default_spec();

        let requests: &[OutboundRequest<Spec>] = &[
            OutboundRequest::Ping(ping_message()),
            OutboundRequest::Status(status_message()),
            OutboundRequest::Goodbye(GoodbyeReason::Fault),
            OutboundRequest::BlocksByRange(bbrange_request_v1()),
            OutboundRequest::BlocksByRange(bbrange_request_v2()),
            OutboundRequest::BlocksByRoot(bbroot_request_v1(&chain_spec)),
            OutboundRequest::BlocksByRoot(bbroot_request_v2(&chain_spec)),
            OutboundRequest::MetaData(MetadataRequest::new_v1()),
            OutboundRequest::BlobsByRange(blbrange_request()),
            OutboundRequest::BlobsByRoot(blbroot_request(&chain_spec)),
            OutboundRequest::MetaData(MetadataRequest::new_v2()),
        ];

        for req in requests.iter() {
            for fork_name in ForkName::list_all() {
                encode_then_decode_request(req.clone(), fork_name, &chain_spec);
            }
        }
    }

    /// Test a malicious snappy encoding for a V1 `Status` message where the attacker
    /// sends a valid message filled with a stream of useless padding before the actual message.
    #[test]
    fn test_decode_malicious_v1_message() {
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

        let chain_spec = Spec::default_spec();
        // 10 (for stream identifier) + 80 + 42 = 132 > `max_compressed_len`. Hence, decoding should fail with `InvalidData`.
        assert!(matches!(
            decode_response(
                SupportedProtocol::StatusV1,
                &mut dst,
                ForkName::Base,
                &chain_spec
            )
            .unwrap_err(),
            RPCError::InvalidData(_)
        ));
    }

    /// Test a malicious snappy encoding for a V2 `BlocksByRange` message where the attacker
    /// sends a valid message filled with a stream of useless padding before the actual message.
    #[test]
    fn test_decode_malicious_v2_message() {
        let fork_context = Arc::new(fork_context(ForkName::Altair));

        // 10 byte snappy stream identifier
        let stream_identifier: &'static [u8] = b"\xFF\x06\x00\x00sNaPpY";

        assert_eq!(stream_identifier.len(), 10);

        // byte 0(0xFE) is padding chunk type identifier for snappy messages
        // byte 1,2,3 are chunk length (little endian)
        let malicious_padding: &'static [u8] = b"\xFE\x00\x00\x00";

        // Full altair block is 157916 bytes uncompressed. `max_compressed_len` is 32 + 157916 + 157916/6 = 184267.
        let block_message_bytes = altair_block().as_ssz_bytes();

        assert_eq!(block_message_bytes.len(), 157916);
        assert_eq!(
            snap::raw::max_compress_len(block_message_bytes.len()),
            184267
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

        // Insert malicious padding of 176156 bytes.
        for _ in 0..44039 {
            dst.extend_from_slice(malicious_padding);
        }

        // Insert payload (8103 bytes compressed)
        let mut writer = FrameEncoder::new(Vec::new());
        writer.write_all(&block_message_bytes).unwrap();
        writer.flush().unwrap();
        assert_eq!(writer.get_ref().len(), 8103);
        dst.extend_from_slice(writer.get_ref());

        let chain_spec = Spec::default_spec();

        // 10 (for stream identifier) + 176156 + 8103 = 184269 > `max_compressed_len`. Hence, decoding should fail with `InvalidData`.
        assert!(matches!(
            decode_response(
                SupportedProtocol::BlocksByRangeV2,
                &mut dst,
                ForkName::Altair,
                &chain_spec,
            )
            .unwrap_err(),
            RPCError::InvalidData(_)
        ));
    }

    /// Test sending a message with encoded length prefix > max_rpc_size.
    #[test]
    fn test_decode_invalid_length() {
        // 10 byte snappy stream identifier
        let stream_identifier: &'static [u8] = b"\xFF\x06\x00\x00sNaPpY";

        assert_eq!(stream_identifier.len(), 10);

        // Status message is 84 bytes uncompressed. `max_compressed_len` is 32 + 84 + 84/6 = 130.
        let status_message_bytes = StatusMessage {
            fork_digest: [0; 4],
            finalized_root: Hash256::from_low_u64_be(0),
            finalized_epoch: Epoch::new(1),
            head_root: Hash256::from_low_u64_be(0),
            head_slot: Slot::new(1),
        }
        .as_ssz_bytes();

        let mut uvi_codec: Uvi<usize> = Uvi::default();
        let mut dst = BytesMut::with_capacity(1024);

        let chain_spec = Spec::default_spec();

        // Insert length-prefix
        uvi_codec
            .encode(chain_spec.max_chunk_size as usize + 1, &mut dst)
            .unwrap();

        // Insert snappy stream identifier
        dst.extend_from_slice(stream_identifier);

        // Insert payload
        let mut writer = FrameEncoder::new(Vec::new());
        writer.write_all(&status_message_bytes).unwrap();
        writer.flush().unwrap();
        dst.extend_from_slice(writer.get_ref());

        assert!(matches!(
            decode_response(
                SupportedProtocol::StatusV1,
                &mut dst,
                ForkName::Base,
                &chain_spec
            )
            .unwrap_err(),
            RPCError::InvalidData(_)
        ));
    }
}
