//! This handles the various supported encoding mechanism for the Eth 2.0 RPC.

use crate::rpc::{ErrorMessage, RPCCodedResponse, RPCRequest, RPCResponse};
use libp2p::bytes::BufMut;
use libp2p::bytes::BytesMut;
use std::marker::PhantomData;
use tokio_util::codec::{Decoder, Encoder};
use types::EthSpec;

pub trait OutboundCodec<TItem>: Encoder<TItem> + Decoder {
    type ErrorType;

    fn decode_error(
        &mut self,
        src: &mut BytesMut,
    ) -> Result<Option<Self::ErrorType>, <Self as Decoder>::Error>;
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
    TCodec: OutboundCodec<RPCRequest<TSpec>, ErrorType = ErrorMessage>
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
    use super::super::ssz::*;
    use super::super::ssz_snappy::*;
    use super::*;
    use crate::rpc::protocol::*;

    #[test]
    fn test_decode_status_message() {
        let message = hex::decode("ff060000734e615070590032000006e71e7b54989925efd6c9cbcb8ceb9b5f71216f5137282bf6a1e3b50f64e42d6c7fb347abe07eb0db8200000005029e2800").unwrap();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&message);

        type Spec = types::MainnetEthSpec;

        let snappy_protocol_id =
            ProtocolId::new(Protocol::Status, Version::V1, Encoding::SSZSnappy);
        let ssz_protocol_id = ProtocolId::new(Protocol::Status, Version::V1, Encoding::SSZ);

        let mut snappy_outbound_codec =
            SSZSnappyOutboundCodec::<Spec>::new(snappy_protocol_id, 1_048_576);
        let mut ssz_outbound_codec = SSZOutboundCodec::<Spec>::new(ssz_protocol_id, 1_048_576);

        // decode message just as snappy message
        let snappy_decoded_message = snappy_outbound_codec.decode(&mut buf.clone());
        // decode message just a ssz message
        let ssz_decoded_message = ssz_outbound_codec.decode(&mut buf.clone());

        // build codecs for entire chunk
        let mut snappy_base_outbound_codec = BaseOutboundCodec::new(snappy_outbound_codec);
        let mut ssz_base_outbound_codec = BaseOutboundCodec::new(ssz_outbound_codec);

        // decode message as ssz snappy chunk
        let snappy_decoded_chunk = snappy_base_outbound_codec.decode(&mut buf.clone());
        // decode message just a ssz chunk
        let ssz_decoded_chunk = ssz_base_outbound_codec.decode(&mut buf.clone());

        let _ = dbg!(snappy_decoded_message);
        let _ = dbg!(ssz_decoded_message);
        let _ = dbg!(snappy_decoded_chunk);
        let _ = dbg!(ssz_decoded_chunk);
    }
}
