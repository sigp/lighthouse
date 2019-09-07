//! This handles the various supported encoding mechanism for the Eth 2.0 RPC.

use crate::rpc::{ErrorMessage, RPCErrorResponse, RPCRequest, RPCResponse};
use bytes::BufMut;
use bytes::BytesMut;
use tokio::codec::{Decoder, Encoder};

pub trait OutboundCodec: Encoder + Decoder {
    type ErrorType;

    fn decode_error(
        &mut self,
        src: &mut BytesMut,
    ) -> Result<Option<Self::ErrorType>, <Self as Decoder>::Error>;
}

pub struct BaseInboundCodec<TCodec>
where
    TCodec: Encoder + Decoder,
{
    /// Inner codec for handling various encodings
    inner: TCodec,
}

impl<TCodec> BaseInboundCodec<TCodec>
where
    TCodec: Encoder + Decoder,
{
    pub fn new(codec: TCodec) -> Self {
        BaseInboundCodec { inner: codec }
    }
}

pub struct BaseOutboundCodec<TOutboundCodec>
where
    TOutboundCodec: OutboundCodec,
{
    /// Inner codec for handling various encodings
    inner: TOutboundCodec,
    /// Optimisation for decoding. True if the response code has been read and we are awaiting a
    /// response.
    response_code: Option<u8>,
}

impl<TOutboundCodec> BaseOutboundCodec<TOutboundCodec>
where
    TOutboundCodec: OutboundCodec,
{
    pub fn new(codec: TOutboundCodec) -> Self {
        BaseOutboundCodec {
            inner: codec,
            response_code: None,
        }
    }
}

impl<TCodec> Encoder for BaseInboundCodec<TCodec>
where
    TCodec: Decoder + Encoder<Item = RPCErrorResponse>,
{
    type Item = RPCErrorResponse;
    type Error = <TCodec as Encoder>::Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.clear();
        dst.reserve(1);
        dst.put_u8(item.as_u8());
        self.inner.encode(item, dst)
    }
}

impl<TCodec> Decoder for BaseInboundCodec<TCodec>
where
    TCodec: Encoder + Decoder<Item = RPCRequest>,
{
    type Item = RPCRequest;
    type Error = <TCodec as Decoder>::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.inner.decode(src)
    }
}

impl<TCodec> Encoder for BaseOutboundCodec<TCodec>
where
    TCodec: OutboundCodec + Encoder<Item = RPCRequest>,
{
    type Item = RPCRequest;
    type Error = <TCodec as Encoder>::Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.inner.encode(item, dst)
    }
}

impl<TCodec> Decoder for BaseOutboundCodec<TCodec>
where
    TCodec: OutboundCodec<ErrorType = ErrorMessage> + Decoder<Item = RPCResponse>,
{
    type Item = RPCErrorResponse;
    type Error = <TCodec as Decoder>::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // if we have only received the response code, wait for more bytes
        if src.len() == 1 {
            return Ok(None);
        }
        // using the response code determine which kind of payload needs to be decoded.
        let response_code = {
            if let Some(resp_code) = self.response_code {
                resp_code
            } else {
                let resp_byte = src.split_to(1);
                let mut resp_code_byte = [0; 1];
                resp_code_byte.copy_from_slice(&resp_byte);

                let resp_code = u8::from_be_bytes(resp_code_byte);
                self.response_code = Some(resp_code);
                resp_code
            }
        };

        if RPCErrorResponse::is_response(response_code) {
            // decode an actual response
            self.inner
                .decode(src)
                .map(|r| r.map(RPCErrorResponse::Success))
        } else {
            // decode an error
            self.inner
                .decode_error(src)
                .map(|r| r.map(|resp| RPCErrorResponse::from_error(response_code, resp)))
        }
    }
}
