use crate::rpc::methods::*;
use crate::rpc::{
    codec::base::OutboundCodec,
    protocol::{
        ProtocolId, RPCError, RPC_BLOCKS_BY_RANGE, RPC_BLOCKS_BY_ROOT, RPC_GOODBYE, RPC_STATUS,
        TESTING,
    },
};
use crate::rpc::{ErrorMessage, RPCErrorResponse, RPCRequest, RPCResponse};
use libp2p::bytes::{Bytes, BytesMut};
use snap::read::FrameDecoder;
use snap::write::FrameEncoder;
use ssz::{Decode, Encode};
use std::io::Cursor;
use std::io::{Read, Write};
use std::marker::PhantomData;
use tokio::codec::{Decoder, Encoder};
use types::{BeaconBlock, EthSpec};
use unsigned_varint::codec::UviBytes;

/* Inbound Codec */

pub struct SSZSnappyInboundCodec<TSpec: EthSpec> {
    encoder: snap::raw::Encoder,
    decoder: snap::raw::Decoder,
    protocol: ProtocolId,
    inner: UviBytes,
    phantom: PhantomData<TSpec>,
    writer: FrameEncoder<Vec<u8>>,
}

impl<T: EthSpec> SSZSnappyInboundCodec<T> {
    pub fn new(protocol: ProtocolId, max_packet_size: usize) -> Self {
        let mut uvi_codec = UviBytes::default();
        uvi_codec.set_max_len(max_packet_size);
        // this encoding only applies to ssz_snappy.
        debug_assert!(protocol.encoding.as_str() == "ssz_snappy");

        SSZSnappyInboundCodec {
            encoder: snap::raw::Encoder::new(),
            decoder: snap::raw::Decoder::new(),
            protocol,
            phantom: PhantomData,
            inner: uvi_codec,
            writer: FrameEncoder::new(Vec::new()),
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
                RPCResponse::Testing(res) => res,
            },
            RPCErrorResponse::InvalidRequest(err) => err.as_ssz_bytes(),
            RPCErrorResponse::ServerError(err) => err.as_ssz_bytes(),
            RPCErrorResponse::Unknown(err) => err.as_ssz_bytes(),
            RPCErrorResponse::StreamTermination(_) => {
                unreachable!("Code error - attempting to encode a stream termination")
            }
        };
        // let compressed_bytes = self.encoder.compress_vec(&bytes).map_err(RPCError::from)?;
        // self.inner
        //     .encode(Bytes::from(compressed_bytes), dst)
        //     .map_err(RPCError::from)
        // println!("Encoder Size of uncompressed bytes: {}", bytes.len());
        let mut writer = FrameEncoder::new(Vec::new());
        writer.write_all(&bytes).map_err(RPCError::from)?;
        writer.flush().map_err(RPCError::from)?;

        // let mut reader = FrameDecoder::new(self.writer.get_ref().as_slice());
        // let mut uncompressed = Vec::new();
        // let a = reader.read_to_end(&mut uncompressed)?;
        // assert_eq!(uncompressed.len(), bytes.len());

        dst.extend_from_slice(writer.get_ref());
        println!("Encoder Size of compressed bytes: {}", dst.len());
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
                TESTING => match self.protocol.version.as_str() {
                    "1" => Ok(Some(RPCRequest::Testing(TestingRequest))),
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
    inner: UviBytes,
    protocol: ProtocolId,
    phantom: PhantomData<TSpec>,
    reader: FrameDecoder<Cursor<Vec<u8>>>,
    decoded_buffer: Vec<u8>,
}

impl<TSpec: EthSpec> SSZSnappyOutboundCodec<TSpec> {
    pub fn new(protocol: ProtocolId, max_packet_size: usize) -> Self {
        let mut uvi_codec = UviBytes::default();
        uvi_codec.set_max_len(max_packet_size);
        // this encoding only applies to ssz_snappy.
        debug_assert!(protocol.encoding.as_str() == "ssz_snappy");

        SSZSnappyOutboundCodec {
            encoder: snap::raw::Encoder::new(),
            decoder: snap::raw::Decoder::new(),
            protocol,
            phantom: PhantomData,
            inner: uvi_codec,
            reader: FrameDecoder::new(Cursor::new(Vec::new())),
            decoded_buffer: Vec::new(),
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
            RPCRequest::Testing(req) => req.as_ssz_bytes(),
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
        const len: usize = 30860;
        println!("Suprabhat");
        println!("Size of src: {}", src.len());
        let mut reader = FrameDecoder::new(Cursor::new(Vec::new()));
        if src.len() < len {
            return Ok(None);
        }
        let inner = reader.get_mut();
        let to_write = src.split_to(len);
        println!(
            "Size of to_write: {} and src after {}",
            to_write.len(),
            src.len()
        );
        inner.write_all(&to_write)?;
        inner.set_position(0);
        // dbg!(self.reader.get_ref());
        match reader.read_to_end(&mut self.decoded_buffer) {
            Ok(0) => {
                dbg!("Dafuq");
                return Ok(None);
            }
            Ok(n) => {
                dbg!(n);
                match self.protocol.message_name.as_str() {
                    RPC_STATUS => match self.protocol.version.as_str() {
                        "1" => {
                            let resp = RPCResponse::Status(StatusMessage::from_ssz_bytes(
                                &self.decoded_buffer,
                            )?);
                            dbg!("Hey a status");
                            self.decoded_buffer.clear();
                            return Ok(Some(resp));
                        }
                        _ => unreachable!("Cannot negotiate an unknown version"),
                    },
                    RPC_GOODBYE => {
                        let resp = RPCError::InvalidProtocol("GOODBYE doesn't have a response");
                        self.decoded_buffer.clear();
                        return Err(resp);
                    }
                    RPC_BLOCKS_BY_RANGE => match self.protocol.version.as_str() {
                        "1" => {
                            let resp = RPCResponse::BlocksByRange(Box::new(
                                BeaconBlock::from_ssz_bytes(&self.decoded_buffer)?,
                            ));
                            self.decoded_buffer.clear();
                            return Ok(Some(resp));
                        }
                        _ => unreachable!("Cannot negotiate an unknown version"),
                    },
                    RPC_BLOCKS_BY_ROOT => match self.protocol.version.as_str() {
                        "1" => {
                            let resp = RPCResponse::BlocksByRoot(Box::new(
                                BeaconBlock::from_ssz_bytes(&self.decoded_buffer)?,
                            ));
                            self.decoded_buffer.clear();
                            dbg!("Hey a block");
                            return Ok(Some(resp));
                        }
                        _ => unreachable!("Cannot negotiate an unknown version"),
                    },
                    TESTING => match self.protocol.version.as_str() {
                        "1" => {
                            let resp = RPCResponse::Testing(self.decoded_buffer.clone());
                            self.decoded_buffer.clear();
                            return Ok(Some(resp));
                        }
                        _ => unreachable!("Cannot negotiate an unknown version"),
                    },
                    _ => unreachable!("Cannot negotiate an unknown protocol"),
                }
            }
            Err(e) => {
                dbg!(&e);
                match e.kind() {
                    std::io::ErrorKind::UnexpectedEof => {
                        // dbg!(e.());
                        return Ok(None);
                    }
                    _ => return Err(e).map_err(RPCError::from),
                }
            }
        }

        // // match self.reader.read_to_end(&mut self.decoded_buffer)? {
        // //     n => {
        // //         if v.
        // //     }
        // // }
        // match self.inner.decode(src).map_err(RPCError::from)? {
        //     Some(compressed_bytes) => {
        //         match self
        //             .decoder
        //             .decompress_vec(&compressed_bytes)
        //             .map_err(RPCError::from)
        //         {
        //             Ok(raw_bytes) => match self.protocol.message_name.as_str() {
        //                 RPC_STATUS => match self.protocol.version.as_str() {
        //                     "1" => {
        //                         return Ok(Some(RPCResponse::Status(
        //                             StatusMessage::from_ssz_bytes(&raw_bytes)?,
        //                         )))
        //                     }
        //                     _ => unreachable!("Cannot negotiate an unknown version"),
        //                 },
        //                 RPC_GOODBYE => {
        //                     return Err(RPCError::InvalidProtocol(
        //                         "GOODBYE doesn't have a response",
        //                     ))
        //                 }
        //                 RPC_BLOCKS_BY_RANGE => match self.protocol.version.as_str() {
        //                     "1" => {
        //                         return Ok(Some(RPCResponse::BlocksByRange(Box::new(
        //                             BeaconBlock::from_ssz_bytes(&raw_bytes)?,
        //                         ))))
        //                     }
        //                     _ => unreachable!("Cannot negotiate an unknown version"),
        //                 },
        //                 RPC_BLOCKS_BY_ROOT => match self.protocol.version.as_str() {
        //                     "1" => {
        //                         return Ok(Some(RPCResponse::BlocksByRoot(Box::new(
        //                             BeaconBlock::from_ssz_bytes(&raw_bytes)?,
        //                         ))))
        //                     }
        //                     _ => unreachable!("Cannot negotiate an unknown version"),
        //                 },
        //                 _ => unreachable!("Cannot negotiate an unknown protocol"),
        //             },
        //             Err(e) => return Err(e),
        //         }
        //     }
        //     None => Ok(None), // waiting for more bytes
        // }
    }
}

impl<TSpec: EthSpec> OutboundCodec for SSZSnappyOutboundCodec<TSpec> {
    type ErrorType = ErrorMessage;

    fn decode_error(&mut self, src: &mut BytesMut) -> Result<Option<Self::ErrorType>, RPCError> {
        match self.decoder.decompress_vec(src).map_err(RPCError::from) {
            Ok(packet) => Ok(Some(ErrorMessage::from_ssz_bytes(&packet)?)),
            Err(e) => {
                println!("Got errror: {:?}", e);
                Err(e)
            }
        }
    }
}

// pub struct SnappyBytes {
//     encoder: snap::Encoder,
//     decoder: snap::Decoder,
//     len: Option<usize>,
// }

// impl SnappyBytes {
//     pub fn new() -> Self {
//         SnappyBytes {
//             encoder: snap::Encoder::new(),
//             decoder: snap::Decoder::new(),
//             len: None,
//         }
//     }
// }
