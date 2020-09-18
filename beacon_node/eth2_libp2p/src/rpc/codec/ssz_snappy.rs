use crate::rpc::methods::*;
use crate::rpc::{
    codec::base::OutboundCodec,
    protocol::{
        Encoding, Protocol, ProtocolId, RPCError, Version, BLOCKS_BY_ROOT_REQUEST_MAX,
        BLOCKS_BY_ROOT_REQUEST_MIN, SIGNED_BEACON_BLOCK_MAX, SIGNED_BEACON_BLOCK_MIN,
    },
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
use tokio_util::codec::{Decoder, Encoder};
use types::{EthSpec, SignedBeaconBlock};
use unsigned_varint::codec::Uvi;

/* Inbound Codec */

pub struct SSZSnappyInboundCodec<TSpec: EthSpec> {
    protocol: ProtocolId,
    inner: Uvi<usize>,
    len: Option<usize>,
    /// Maximum bytes that can be sent in one req/resp chunked responses.
    max_packet_size: usize,
    phantom: PhantomData<TSpec>,
}

impl<T: EthSpec> SSZSnappyInboundCodec<T> {
    pub fn new(protocol: ProtocolId, max_packet_size: usize) -> Self {
        let uvi_codec = Uvi::default();
        // this encoding only applies to ssz_snappy.
        debug_assert_eq!(protocol.encoding, Encoding::SSZSnappy);

        SSZSnappyInboundCodec {
            inner: uvi_codec,
            protocol,
            len: None,
            phantom: PhantomData,
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
        let bytes = match item {
            RPCCodedResponse::Success(resp) => match resp {
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
        if self.len.is_none() {
            // Decode the length of the uncompressed bytes from an unsigned varint
            // Note: length-prefix of > 10 bytes(uint64) would be a decoding error
            match self.inner.decode(src).map_err(RPCError::from)? {
                Some(length) => {
                    self.len = Some(length);
                }
                None => return Ok(None), // need more bytes to decode length
            }
        };

        let length = self.len.expect("length should be Some");

        // Should not attempt to decode rpc chunks with length > max_packet_size
        if length > self.max_packet_size {
            return Err(RPCError::InvalidData);
        }
        let mut reader = FrameDecoder::new(Cursor::new(&src));
        let mut decoded_buffer = vec![0; length];

        match read_exact(&mut reader, &mut decoded_buffer, length) {
            Ok(()) => {
                // `n` is how many bytes the reader read in the compressed stream
                let n = reader.get_ref().position();
                self.len = None;
                let _read_bytes = src.split_to(n as usize);
                match self.protocol.message_name {
                    Protocol::Status => match self.protocol.version {
                        Version::V1 => {
                            if decoded_buffer.len() == <StatusMessage as Encode>::ssz_fixed_len() {
                                Ok(Some(RPCRequest::Status(StatusMessage::from_ssz_bytes(
                                    &decoded_buffer,
                                )?)))
                            } else {
                                Err(RPCError::InvalidData)
                            }
                        }
                    },
                    Protocol::Goodbye => match self.protocol.version {
                        Version::V1 => {
                            if decoded_buffer.len() == <GoodbyeReason as Encode>::ssz_fixed_len() {
                                Ok(Some(RPCRequest::Goodbye(GoodbyeReason::from_ssz_bytes(
                                    &decoded_buffer,
                                )?)))
                            } else {
                                Err(RPCError::InvalidData)
                            }
                        }
                    },
                    Protocol::BlocksByRange => match self.protocol.version {
                        Version::V1 => {
                            if decoded_buffer.len()
                                == <BlocksByRangeRequest as Encode>::ssz_fixed_len()
                            {
                                Ok(Some(RPCRequest::BlocksByRange(
                                    BlocksByRangeRequest::from_ssz_bytes(&decoded_buffer)?,
                                )))
                            } else {
                                Err(RPCError::InvalidData)
                            }
                        }
                    },
                    Protocol::BlocksByRoot => match self.protocol.version {
                        Version::V1 => {
                            if decoded_buffer.len() >= *BLOCKS_BY_ROOT_REQUEST_MIN
                                && decoded_buffer.len() <= *BLOCKS_BY_ROOT_REQUEST_MAX
                            {
                                Ok(Some(RPCRequest::BlocksByRoot(BlocksByRootRequest {
                                    block_roots: VariableList::from_ssz_bytes(&decoded_buffer)?,
                                })))
                            } else {
                                Err(RPCError::InvalidData)
                            }
                        }
                    },
                    Protocol::Ping => match self.protocol.version {
                        Version::V1 => {
                            if decoded_buffer.len() == <Ping as Encode>::ssz_fixed_len() {
                                Ok(Some(RPCRequest::Ping(Ping {
                                    data: u64::from_ssz_bytes(&decoded_buffer)?,
                                })))
                            } else {
                                Err(RPCError::InvalidData)
                            }
                        }
                    },
                    Protocol::MetaData => match self.protocol.version {
                        Version::V1 => {
                            if !decoded_buffer.is_empty() {
                                Err(RPCError::InvalidData)
                            } else {
                                Ok(Some(RPCRequest::MetaData(PhantomData)))
                            }
                        }
                    },
                }
            }
            Err(e) => match e.kind() {
                // Haven't received enough bytes to decode yet, wait for more
                ErrorKind::UnexpectedEof => Ok(None),
                _ => Err(e).map_err(RPCError::from),
            },
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
    phantom: PhantomData<TSpec>,
}

impl<TSpec: EthSpec> SSZSnappyOutboundCodec<TSpec> {
    pub fn new(protocol: ProtocolId, max_packet_size: usize) -> Self {
        let uvi_codec = Uvi::default();
        // this encoding only applies to ssz_snappy.
        debug_assert_eq!(protocol.encoding, Encoding::SSZSnappy);

        SSZSnappyOutboundCodec {
            inner: uvi_codec,
            protocol,
            max_packet_size,
            len: None,
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
        if self.len.is_none() {
            // Decode the length of the uncompressed bytes from an unsigned varint
            // Note: length-prefix of > 10 bytes(uint64) would be a decoding error
            match self.inner.decode(src).map_err(RPCError::from)? {
                Some(length) => {
                    self.len = Some(length as usize);
                }
                None => return Ok(None), // need more bytes to decode length
            }
        };

        let length = self.len.expect("length should be Some");

        // Should not attempt to decode rpc chunks with length > max_packet_size
        if length > self.max_packet_size {
            return Err(RPCError::InvalidData);
        }
        let mut reader = FrameDecoder::new(Cursor::new(&src));
        let mut decoded_buffer = vec![0; length];
        match read_exact(&mut reader, &mut decoded_buffer, length) {
            Ok(()) => {
                // `n` is how many bytes the reader read in the compressed stream
                let n = reader.get_ref().position();
                self.len = None;
                let _read_byts = src.split_to(n as usize);
                match self.protocol.message_name {
                    Protocol::Status => match self.protocol.version {
                        Version::V1 => {
                            if decoded_buffer.len() == <StatusMessage as Encode>::ssz_fixed_len() {
                                Ok(Some(RPCResponse::Status(StatusMessage::from_ssz_bytes(
                                    &decoded_buffer,
                                )?)))
                            } else {
                                Err(RPCError::InvalidData)
                            }
                        }
                    },
                    Protocol::Goodbye => Err(RPCError::InvalidData),
                    Protocol::BlocksByRange => match self.protocol.version {
                        Version::V1 => {
                            if decoded_buffer.len() >= *SIGNED_BEACON_BLOCK_MIN
                                && decoded_buffer.len() <= *SIGNED_BEACON_BLOCK_MAX
                            {
                                Ok(Some(RPCResponse::BlocksByRange(Box::new(
                                    SignedBeaconBlock::from_ssz_bytes(&decoded_buffer)?,
                                ))))
                            } else {
                                Err(RPCError::InvalidData)
                            }
                        }
                    },
                    Protocol::BlocksByRoot => match self.protocol.version {
                        Version::V1 => {
                            if decoded_buffer.len() >= *SIGNED_BEACON_BLOCK_MIN
                                && decoded_buffer.len() <= *SIGNED_BEACON_BLOCK_MAX
                            {
                                Ok(Some(RPCResponse::BlocksByRoot(Box::new(
                                    SignedBeaconBlock::from_ssz_bytes(&decoded_buffer)?,
                                ))))
                            } else {
                                Err(RPCError::InvalidData)
                            }
                        }
                    },
                    Protocol::Ping => match self.protocol.version {
                        Version::V1 => {
                            if decoded_buffer.len() == <Ping as Encode>::ssz_fixed_len() {
                                Ok(Some(RPCResponse::Pong(Ping {
                                    data: u64::from_ssz_bytes(&decoded_buffer)?,
                                })))
                            } else {
                                Err(RPCError::InvalidData)
                            }
                        }
                    },
                    Protocol::MetaData => match self.protocol.version {
                        Version::V1 => {
                            if decoded_buffer.len() == <MetaData<TSpec> as Encode>::ssz_fixed_len()
                            {
                                Ok(Some(RPCResponse::MetaData(MetaData::from_ssz_bytes(
                                    &decoded_buffer,
                                )?)))
                            } else {
                                Err(RPCError::InvalidData)
                            }
                        }
                    },
                }
            }
            Err(e) => match e.kind() {
                // Haven't received enough bytes to decode yet, wait for more
                ErrorKind::UnexpectedEof => Ok(None),
                _ => Err(e).map_err(RPCError::from),
            },
        }
    }
}

impl<TSpec: EthSpec> OutboundCodec<RPCRequest<TSpec>> for SSZSnappyOutboundCodec<TSpec> {
    type CodecErrorType = ErrorType;

    fn decode_error(
        &mut self,
        src: &mut BytesMut,
    ) -> Result<Option<Self::CodecErrorType>, RPCError> {
        if self.len.is_none() {
            // Decode the length of the uncompressed bytes from an unsigned varint
            match self.inner.decode(src).map_err(RPCError::from)? {
                Some(length) => {
                    self.len = Some(length as usize);
                }
                None => return Ok(None), // need more bytes to decode length
            }
        };

        let length = self.len.expect("length should be Some");

        // Should not attempt to decode rpc chunks with length > max_packet_size
        if length > self.max_packet_size {
            return Err(RPCError::InvalidData);
        }
        let mut reader = FrameDecoder::new(Cursor::new(&src));
        let mut decoded_buffer = vec![0; length];
        match read_exact(&mut reader, &mut decoded_buffer, length) {
            Ok(()) => {
                // `n` is how many bytes the reader read in the compressed stream
                let n = reader.get_ref().position();
                self.len = None;
                let _read_bytes = src.split_to(n as usize);
                Ok(Some(ErrorType(VariableList::from_ssz_bytes(
                    &decoded_buffer,
                )?)))
            }
            Err(e) => match e.kind() {
                // Haven't received enough bytes to decode yet, wait for more
                ErrorKind::UnexpectedEof => Ok(None),
                _ => Err(e).map_err(RPCError::from),
            },
        }
    }
}

/// Wrapper over `read` implementation of `FrameDecoder`.
///
/// Works like the standard `read_exact` implementation, except that it returns an error if length of
// compressed bytes read from the underlying reader is greater than worst case compression length for snappy.
fn read_exact<T: std::convert::AsRef<[u8]>>(
    reader: &mut FrameDecoder<Cursor<T>>,
    mut buf: &mut [u8],
    uncompressed_length: usize,
) -> Result<(), std::io::Error> {
    // Calculate worst case compression length for given uncompressed length
    let max_compressed_len = snap::raw::max_compress_len(uncompressed_length) as u64;

    // Initialize the position of the reader
    let mut pos = reader.get_ref().position();
    let mut count = 0;
    while !buf.is_empty() {
        match reader.read(buf) {
            Ok(0) => break,
            Ok(n) => {
                let tmp = buf;
                buf = &mut tmp[n..];
            }
            Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
        // Get current position of reader
        let curr_pos = reader.get_ref().position();
        // Note: reader should always advance forward. However, this behaviour
        // depends on the implementation of `snap::FrameDecoder`, so it is better
        // to check to avoid underflow panic.
        if curr_pos > pos {
            count += reader.get_ref().position() - pos;
            pos = curr_pos;
        } else {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "snappy: reader is not advanced forward while reading",
            ));
        }

        if count > max_compressed_len {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "snappy: compressed data is > max_compressed_len",
            ));
        }
    }
    if !buf.is_empty() {
        Err(std::io::Error::new(
            ErrorKind::UnexpectedEof,
            "failed to fill whole buffer",
        ))
    } else {
        Ok(())
    }
}
