//! This handles the various supported encoding mechanism for the Eth 2.0 RPC.

use crate::rpc::methods::ErrorType;
use crate::rpc::{RPCCodedResponse, RPCRequest, RPCResponse};
use libp2p::bytes::BufMut;
use libp2p::bytes::BytesMut;
use std::marker::PhantomData;
use tokio_util::codec::{Decoder, Encoder};
use types::EthSpec;

pub trait OutboundCodec<TItem>: Encoder<TItem> + Decoder {
    type CodecErrorType;

    fn decode_error(
        &mut self,
        src: &mut BytesMut,
    ) -> Result<Option<Self::CodecErrorType>, <Self as Decoder>::Error>;
}

/* Global Inbound Codec */
// This deals with Decoding RPC Requests from other peers and encoding our responses

pub struct BaseInboundCodec<TCodec, TSpec>
where
    TCodec: Encoder<RPCCodedResponse<TSpec>> + Decoder,
    TSpec: EthSpec,
{
    /// Inner codec for handling various encodings
    inner: TCodec,
    phantom: PhantomData<TSpec>,
}

impl<TCodec, TSpec> BaseInboundCodec<TCodec, TSpec>
where
    TCodec: Encoder<RPCCodedResponse<TSpec>> + Decoder,
    TSpec: EthSpec,
{
    pub fn new(codec: TCodec) -> Self {
        BaseInboundCodec {
            inner: codec,
            phantom: PhantomData,
        }
    }
}

/* Global Outbound Codec */
// This deals with Decoding RPC Responses from other peers and encoding our requests
pub struct BaseOutboundCodec<TOutboundCodec, TSpec>
where
    TOutboundCodec: OutboundCodec<RPCRequest<TSpec>>,
    TSpec: EthSpec,
{
    /// Inner codec for handling various encodings.
    inner: TOutboundCodec,
    /// Keeps track of the current response code for a chunk.
    current_response_code: Option<u8>,
    phantom: PhantomData<TSpec>,
}

impl<TOutboundCodec, TSpec> BaseOutboundCodec<TOutboundCodec, TSpec>
where
    TSpec: EthSpec,
    TOutboundCodec: OutboundCodec<RPCRequest<TSpec>>,
{
    pub fn new(codec: TOutboundCodec) -> Self {
        BaseOutboundCodec {
            inner: codec,
            current_response_code: None,
            phantom: PhantomData,
        }
    }
}

/* Implementation of the Encoding/Decoding for the global codecs */

/* Base Inbound Codec */

// This Encodes RPC Responses sent to external peers
impl<TCodec, TSpec> Encoder<RPCCodedResponse<TSpec>> for BaseInboundCodec<TCodec, TSpec>
where
    TSpec: EthSpec,
    TCodec: Decoder + Encoder<RPCCodedResponse<TSpec>>,
{
    type Error = <TCodec as Encoder<RPCCodedResponse<TSpec>>>::Error;

    fn encode(
        &mut self,
        item: RPCCodedResponse<TSpec>,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        dst.clear();
        dst.reserve(1);
        dst.put_u8(
            item.as_u8()
                .expect("Should never encode a stream termination"),
        );
        self.inner.encode(item, dst)
    }
}

// This Decodes RPC Requests from external peers
impl<TCodec, TSpec> Decoder for BaseInboundCodec<TCodec, TSpec>
where
    TSpec: EthSpec,
    TCodec: Encoder<RPCCodedResponse<TSpec>> + Decoder<Item = RPCRequest<TSpec>>,
{
    type Item = RPCRequest<TSpec>;
    type Error = <TCodec as Decoder>::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.inner.decode(src)
    }
}

/* Base Outbound Codec */

// This Encodes RPC Requests sent to external peers
impl<TCodec, TSpec> Encoder<RPCRequest<TSpec>> for BaseOutboundCodec<TCodec, TSpec>
where
    TSpec: EthSpec,
    TCodec: OutboundCodec<RPCRequest<TSpec>> + Encoder<RPCRequest<TSpec>>,
{
    type Error = <TCodec as Encoder<RPCRequest<TSpec>>>::Error;

    fn encode(&mut self, item: RPCRequest<TSpec>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.inner.encode(item, dst)
    }
}

// This decodes RPC Responses received from external peers
impl<TCodec, TSpec> Decoder for BaseOutboundCodec<TCodec, TSpec>
where
    TSpec: EthSpec,
    TCodec: OutboundCodec<RPCRequest<TSpec>, CodecErrorType = ErrorType>
        + Decoder<Item = RPCResponse<TSpec>>,
{
    type Item = RPCCodedResponse<TSpec>;
    type Error = <TCodec as Decoder>::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // if we have only received the response code, wait for more bytes
        if src.len() <= 1 {
            return Ok(None);
        }
        // using the response code determine which kind of payload needs to be decoded.
        let response_code = self.current_response_code.unwrap_or_else(|| {
            let resp_code = src.split_to(1)[0];
            self.current_response_code = Some(resp_code);
            resp_code
        });

        let inner_result = {
            if RPCCodedResponse::<TSpec>::is_response(response_code) {
                // decode an actual response and mutates the buffer if enough bytes have been read
                // returning the result.
                self.inner
                    .decode(src)
                    .map(|r| r.map(RPCCodedResponse::Success))
            } else {
                // decode an error
                self.inner
                    .decode_error(src)
                    .map(|r| r.map(|resp| RPCCodedResponse::from_error(response_code, resp)))
            }
        };
        // if the inner decoder was capable of decoding a chunk, we need to reset the current
        // response code for the next chunk
        if let Ok(Some(_)) = inner_result {
            self.current_response_code = None;
        }
        // return the result
        inner_result
    }
}

#[cfg(test)]
mod tests {
    use super::super::ssz_snappy::*;
    use super::*;
    use crate::rpc::methods::StatusMessage;
    use crate::rpc::protocol::*;
    use snap::write::FrameEncoder;
    use ssz::Encode;
    use std::io::Write;
    use types::{Epoch, Hash256, Slot};
    use unsigned_varint::codec::Uvi;

    type Spec = types::MainnetEthSpec;

    #[test]
    fn test_decode_status_message() {
        let message = hex::decode("ff060000734e615070590032000006e71e7b54989925efd6c9cbcb8ceb9b5f71216f5137282bf6a1e3b50f64e42d6c7fb347abe07eb0db8200000005029e2800").unwrap();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&message);

        let snappy_protocol_id =
            ProtocolId::new(Protocol::Status, Version::V1, Encoding::SSZSnappy);

        let mut snappy_outbound_codec =
            SSZSnappyOutboundCodec::<Spec>::new(snappy_protocol_id, 1_048_576);

        // decode message just as snappy message
        let snappy_decoded_message = snappy_outbound_codec.decode(&mut buf.clone());
        // decode message just a ssz message

        // build codecs for entire chunk
        let mut snappy_base_outbound_codec = BaseOutboundCodec::new(snappy_outbound_codec);

        // decode message as ssz snappy chunk
        let snappy_decoded_chunk = snappy_base_outbound_codec.decode(&mut buf.clone());
        // decode message just a ssz chunk

        let _ = dbg!(snappy_decoded_message);
        let _ = dbg!(snappy_decoded_chunk);
    }

    #[test]
    fn test_decode_malicious_status_message() {
        // Snappy stream identifier
        let stream_identifier: &'static [u8] = b"\xFF\x06\x00\x00sNaPpY";

        // byte 0(0xFE) is padding chunk type identifier for snappy messages
        // byte 1,2,3 are chunk length (little endian)
        let malicious_padding: &'static [u8] = b"\xFE\x00\x00\x00";

        // Status message is 84 bytes uncompressed. `max_compressed_len` is 130.
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
        dst.extend_from_slice(writer.get_ref());

        // 42 + 80 = 132 > max_compressed_len. Hence, decoding should fail with `InvalidData`.

        let snappy_protocol_id =
            ProtocolId::new(Protocol::Status, Version::V1, Encoding::SSZSnappy);

        let mut snappy_outbound_codec =
            SSZSnappyOutboundCodec::<Spec>::new(snappy_protocol_id, 1_048_576);

        let snappy_decoded_message = snappy_outbound_codec.decode(&mut dst.clone()).unwrap_err();
        assert_eq!(snappy_decoded_message, RPCError::InvalidData);
    }
}
