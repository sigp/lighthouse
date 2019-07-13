///! This handles the various supported encoding mechanism for the Eth 2.0 RPC.

pub trait InnerCodec: Encoder + Decoder {
    type Error;

    fn decode_error(
        &mut self,
        &mut BytesMut,
    ) -> Result<Option<Self::Error>, <Self as Decoder>::Error>;
}

pub struct BaseInboundCodec<TCodec: InnerCodec> {
    /// Inner codec for handling various encodings
    inner: TCodec,
}

pub struct BaseOutboundCodec<TCodec>
where
    TCodec: InnerCodec,
    <TCodec as Decoder>::Item = RPCResponse,
    <TCodec as InnerCodec>::ErrorItem = ErrorMessage,
{
    /// Inner codec for handling various encodings
    inner: TCodec,
    /// Optimisation for decoding. True if the response code has been read and we are awaiting a
    /// response.
    response_code: Option<u8>,
}

impl<TCodec> Encoder for BaseInboundCodec<TCodec>
where
    TCodec: Encoder,
    <TCodec as Encoder>::Item = RPCResponse,
{
    type Item = RPCResponse;
    type Error = <TCodec as Encoder>::Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.clear();
        dst.reserve(1);
        dst.put_u8(item.as_u8);
        return self.inner.encode();
    }
}

impl<TCodec> Decoder for BaseInboundCodec<TCodec>
where
    TCodec: Decoder,
    <TCodec as Decoder>::Item: RPCrequest,
    <TCodec as Decoder>::Error: From<RPCError>,
{
    type Item = RPCRequest;
    type Error = <TCodec as Decoder>::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.inner.decode(src)
    }
}

impl<TCodec> Encoder for BaseOutboundCodec<TCodec>
where
    TCodec: Encoder,
{
    type Item = RPCRequest;
    type Error = <TCodec as Encoder>::Error;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.inner.encode(item, dst)
    }
}

impl<TCodec> Decoder for BaseOutboundCodec<TCodec>
where
    TCodec: InnerCodec,
    <TCodec as Decoder>::Error: From<RPCError>,
{
    type Item = RPCResponse;
    type Error = <TCodec as Decoder>::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let response_code = {
            if let Some(resp_code) = self.response_code {
                resp_code;
            } else {
                if src.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "no bytes received",
                    ));
                }
                let resp_byte = src.split_to(1);
                let resp_code_byte = [0; 1];
                resp_code_byte.copy_from_slice(&resp_byte);

                let resp_code = u8::from_be_bytes(resp_code_byte);

                if let Some(response) = RPCErrorResponse::internal_data(resp_code) {
                    self.response_code = None;
                    return response;
                }
                resp_code
            }
        };

        if RPCErrorResponse::is_response(response_code) {
            // decode an actual response
            return self
                .inner
                .decode(src)
                .map(|r| r.map(|resp| RPCErrorResponse::Success(resp)));
        } else {
            // decode an error
            return self
                .inner
                .decode_error(src)
                .map(|r| r.map(|resp| RPCErrorResponse::from_error(response_code, resp)));
        }
    }
}
