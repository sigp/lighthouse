//! This handles the various supported encoding mechanism for the Eth 2.0 RPC.

use crate::rpc::{ErrorMessage, RPCErrorResponse, RPCRequest, RPCResponse};
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

pub struct BaseInboundCodec<TCodec, TSpec, TItem>
where
    TCodec: Encoder<TItem> + Decoder,
    TSpec: EthSpec,
{
    /// Inner codec for handling various encodings
    inner: TCodec,
    phantom: PhantomData<TSpec>,
}

impl<TCodec, TSpec, TItem> BaseInboundCodec<TCodec, TSpec, TItem>
where
    TCodec: Encoder<TItem> + Decoder,
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
pub struct BaseOutboundCodec<TOutboundCodec, TSpec, TItem>
where
    TOutboundCodec: OutboundCodec<TItem>,
    TSpec: EthSpec,
{
    /// Inner codec for handling various encodings.
    inner: TOutboundCodec,
    /// Keeps track of the current response code for a chunk.
    current_response_code: Option<u8>,
    phantom: PhantomData<TSpec>,
}

impl<TOutboundCodec, TSpec, TItem> BaseOutboundCodec<TOutboundCodec, TSpec, TItem>
where
    TSpec: EthSpec,
    TOutboundCodec: OutboundCodec<TItem>,
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
impl<TCodec, TSpec> Encoder<RPCErrorResponse<TSpec>> for BaseInboundCodec<TCodec, TSpec, RPCErrorResponse<TSpec>>
where
    TSpec: EthSpec,
    TCodec: Decoder + Encoder<RPCErrorResponse<TSpec>>,
{
    type Error = <TCodec as Encoder<RPCErrorResponse<TSpec>>>::Error;

    fn encode(&mut self, item: RPCErrorResponse<TSpec>, dst: &mut BytesMut) -> Result<(), Self::Error> {
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
// TODO: check if the Item parameter is correct
impl<TCodec, TSpec> Decoder for BaseInboundCodec<TCodec, TSpec, RPCErrorResponse<TSpec>>
where
    TSpec: EthSpec,
    // TODO: check if the Item parameter is correct
    TCodec: Encoder<RPCErrorResponse<TSpec>> + Decoder<Item = RPCRequest<TSpec>>,
{
    type Item = RPCRequest<TSpec>;
    type Error = <TCodec as Decoder>::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.inner.decode(src)
    }
}

/* Base Outbound Codec */

// This Encodes RPC Requests sent to external peers
impl<TCodec, TSpec> Encoder<RPCRequest<TSpec>> for BaseOutboundCodec<TCodec, TSpec, RPCRequest<TSpec>>
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
impl<TCodec, TSpec> Decoder for BaseOutboundCodec<TCodec, TSpec, RPCRequest<TSpec>>
where
    TSpec: EthSpec,
    TCodec: OutboundCodec<RPCRequest<TSpec>, ErrorType = ErrorMessage> + Decoder<Item = RPCResponse<TSpec>>,
{
    type Item = RPCErrorResponse<TSpec>;
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
            if RPCErrorResponse::<TSpec>::is_response(response_code) {
                // decode an actual response and mutates the buffer if enough bytes have been read
                // returning the result.
                self.inner
                    .decode(src)
                    .map(|r| r.map(RPCErrorResponse::Success))
            } else {
                // decode an error
                self.inner
                    .decode_error(src)
                    .map(|r| r.map(|resp| RPCErrorResponse::from_error(response_code, resp)))
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
