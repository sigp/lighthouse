//! This handles the various supported encoding mechanism for the Eth 2.0 RPC.

use crate::rpc::{protocol::ProtocolId, ErrorMessage, RPCErrorResponse, RPCRequest, RPCResponse};
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
    /// The current protocol id to distinguish whether we expect a single or multiple response chunks
    protocol: ProtocolId,
    /// Optimisation for decoding. True if the response code has been read and we are awaiting a
    /// response.
    past_response_code: Option<u8>,
    /// The current decoded chunks that have been processed from the network.
    chunks: Vec<RPCErrorResponse>,
}

impl<TOutboundCodec> BaseOutboundCodec<TOutboundCodec>
where
    TOutboundCodec: OutboundCodec,
{
    pub fn new(protocol: ProtocolId, codec: TOutboundCodec) -> Self {
        BaseOutboundCodec {
            inner: codec,
            protocol,
            past_response_code: None,
            chunks: Vec::new(),
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
    type Item = Vec<RPCErrorResponse>;
    type Error = <TCodec as Decoder>::Error;

    //TODO: Re-evaluate this decoding strategy for performance gains.
    /// Decodes multiples `response_chunks` which contain a response code and a payload. This
    /// decodes chunks as they come and will terminate a stream on error. As a chunk has completed
    /// without an error, it is removed from the buffer and added to self.chunks.
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            // EOF
            return Ok(Some(self.chunks));
        }

        // if we have only received the response code, wait for more bytes
        if src.len() == 1 {
            return Ok(None);
        }
        // using the response code determine which kind of payload needs to be decoded.
        let response_code = {
            if let Some(resp_code) = self.past_response_code {
                resp_code
            } else {
                let resp_byte = src.split_to(1);
                let mut resp_code_byte = [0; 1];
                resp_code_byte.copy_from_slice(&resp_byte);

                let resp_code = u8::from_be_bytes(resp_code_byte);
                self.past_response_code = Some(resp_code);
                resp_code
            }
        };

        // If we need to request further chunks, batch them, otherwise return the result
        match self.protocol.message_name.as_str() {
            "blocks_by_range" | "blocks_by_root" => {
                // these methods have multiple chunks

                if RPCErrorResponse::is_response(response_code) {
                    match self
                        .inner
                        .decode(src)
                        .map(|r| r.map(RPCErrorResponse::Success))
                    {
                        Ok(Some(rpc_error_response)) => {
                            // add the chunk, reset the past response code and wait for another
                            // chunk
                            self.chunks.push(rpc_error_response);
                            self.past_response_code = None;
                            Ok(None) // wait for another chunk
                        }
                        Ok(None) => Ok(None),
                        Err(e) => Err(e),
                    }
                } else {
                    // decode an error
                    match self
                        .inner
                        .decode_error(src)
                        .map(|r| r.map(|resp| RPCErrorResponse::from_error(response_code, resp)))
                    {
                        // if this errors throw away the batch and log an error.
                        // If this succeeds add the error response to the list and return the batch
                        Ok(Some(error_response)) => {
                            self.chunks.push(error_response);
                            Ok(Some(self.chunks))
                        }
                        Ok(None) => Ok(None),
                        Err(e) => Err(e),
                    }
                }
            }
            "hello" | "goodbye" => {
                // these methods have a single response chunk
                if RPCErrorResponse::is_response(response_code) {
                    // decode an actual response and mutates the buffer if enough bytes have been read
                    // returning the result.
                    self.inner
                        .decode(src)
                        .map(|r| r.map(RPCErrorResponse::Success).map(|v| vec![v]))
                } else {
                    // decode an error
                    self.inner.decode_error(src).map(|r| {
                        r.map(|resp| RPCErrorResponse::from_error(response_code, resp))
                            .map(|v| vec![v])
                    })
                }
            }
        }
    }
}
