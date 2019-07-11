use super::protocol::{ProtocolId, RPCError, RPCResponse, ResponseCode};
use futures::prelude::*;
use futures::try_ready;
use libp2p::core::upgrade::{read_one, ReadOne, ReadOneError};
use std::mem;
use tokio_io::{io, AsyncRead, AsyncWrite};

/// Sends a message over a socket, waits for a response code, then optionally waits for a response.
///
/// The response code is a 1-byte code which determines whether the request succeeded or not.
/// Depending on the response-code, an error may be returned. On success, a response is then
/// retrieved if required.

/// This function also gives an option to terminate the socket and return a default value, allowing for
/// one-shot requests.
///
/// The `short_circuit_return` parameter, if specified, returns the value without awaiting for a
/// response to a request and performing the logic in `then`.
#[inline]
pub fn rpc_request_response<TSocket, TData>(
    socket: TSocket,
    data: TData,                               // data sent as a request
    max_size: usize,                           // maximum bytes to read in a response
    short_circuit_return: Option<RPCResponse>, // default value to return right after a request, do not wait for a response
    protocol: ProtocolId,                      // the protocol being negotiated
) -> RPCRequestResponse<TSocket, TData>
where
    TSocket: AsyncRead + AsyncWrite,
    TData: AsRef<[u8]>,
{
    RPCRequestResponse {
        protocol,
        inner: RPCRequestResponseInner::Write(
            write_one(socket, data).inner,
            max_size,
            short_circuit_return,
        ),
    }
}

/// Future that makes `rpc_request_response` work.
pub struct RPCRequestResponse<TSocket, TData = Vec<u8>> {
    protocol: ProtocolId,
    inner: RPCRequestResponseInner<TSocket, TData>,
}

enum RPCRequestResponseInner<TSocket, TData> {
    // We need to write data to the socket.
    Write(WriteOneInner<TSocket, TData>, usize, Option<RPCResponse>),
    // We need to read the response code.
    ReadResponseCode(io::ReadExact<TSocket, io::Window<Vec<u8>>>, usize),
    // We need to read a final data packet. The second parameter is the response code
    Read(ReadOne<TSocket>, ResponseCode),
    // An error happened during the processing.
    Poisoned,
}

impl<TSocket, TData> Future for RPCRequestResponse<TSocket, TData>
where
    TSocket: AsyncRead + AsyncWrite,
    TData: AsRef<[u8]>,
{
    type Item = RPCResponse;
    type Error = RPCError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match mem::replace(&mut self.inner, RPCRequestResponseInner::Poisoned) {
                RPCRequestResponseInner::Write(mut inner, max_size, sc_return) => {
                    match inner.poll().map_err(ReadOneError::Io)? {
                        Async::Ready(socket) => {
                            // short-circuit the future if `short_circuit_return` is specified
                            if let Some(return_val) = sc_return {
                                return Ok(Async::Ready(return_val));
                            }

                            // begin reading the 1-byte response code
                            let mut data_buf = vec![0; 1];
                            let mut data_buf = io::Window::new(data_buf);
                            self.inner = RPCRequestResponseInner::ReadResponseCode(
                                io::read_exact(socket, data_buf),
                                max_size,
                            );
                        }
                        Async::NotReady => {
                            self.inner = RPCRequestResponseInner::Write(inner, max_size, sc_return);
                            return Ok(Async::NotReady);
                        }
                    }
                }
                RPCRequestResponseInner::ReadResponseCode(mut inner, max_size) => {
                    match inner.poll()? {
                        Async::Ready((socket, data)) => {
                            let resp_code_byte = [0; 1];
                            // data must be only 1-byte - this cannot panic
                            resp_code_byte.copy_from_slice(&data.into_inner());
                            let response_code =
                                ResponseCode::from(u8::from_be_bytes(resp_code_byte));
                            // known response codes
                            match response_code {
                                ResponseCode::Success
                                | ResponseCode::InvalidRequest
                                | ResponseCode::ServerError => {
                                    // need to read another packet
                                    self.inner = RPCRequestResponseInner::Read(
                                        read_one(socket, max_size),
                                        response_code,
                                    )
                                }
                                ResponseCode::EncodingError => {
                                    // invalid encoding
                                    let response = RPCResponse::Error("Invalid Encoding".into());
                                    return Ok(Async::Ready(response));
                                }
                                ResponseCode::Unknown => {
                                    // unknown response code
                                    let response = RPCResponse::Error(format!(
                                        "Unknown response code: {}",
                                        (response_code as u8)
                                    ));
                                    return Ok(Async::Ready(response));
                                }
                            }
                        }
                        Async::NotReady => {
                            self.inner = RPCRequestResponseInner::ReadResponseCode(inner, max_size);
                            return Ok(Async::NotReady);
                        }
                    }
                }
                RPCRequestResponseInner::Read(mut inner, response_code) => match inner.poll()? {
                    Async::Ready(packet) => {
                        return Ok(Async::Ready(RPCResponse::decode(
                            packet,
                            self.protocol,
                            response_code,
                        )?))
                    }
                    Async::NotReady => {
                        self.inner = RPCRequestResponseInner::Read(inner, response_code);
                        return Ok(Async::NotReady);
                    }
                },
                RPCRequestResponseInner::Poisoned => panic!(),
            };
        }
    }
}

/* Copied from rust-libp2p (https://github.com/libp2p/rust-libp2p) to access private members */

/// Send a message to the given socket, then shuts down the writing side.
///
/// > **Note**: Prepends a variable-length prefix indicate the length of the message. This is
/// >           compatible with what `read_one` expects.
#[inline]
pub fn write_one<TSocket, TData>(socket: TSocket, data: TData) -> WriteOne<TSocket, TData>
where
    TSocket: AsyncWrite,
    TData: AsRef<[u8]>,
{
    let len_data = build_int_buffer(data.as_ref().len());
    WriteOne {
        inner: WriteOneInner::WriteLen(io::write_all(socket, len_data), data),
    }
}

enum WriteOneInner<TSocket, TData> {
    /// We need to write the data length to the socket.
    WriteLen(io::WriteAll<TSocket, io::Window<[u8; 10]>>, TData),
    /// We need to write the actual data to the socket.
    Write(io::WriteAll<TSocket, TData>),
    /// We need to shut down the socket.
    Shutdown(io::Shutdown<TSocket>),
    /// A problem happened during the processing.
    Poisoned,
}

impl<TSocket, TData> Future for WriteOneInner<TSocket, TData>
where
    TSocket: AsyncWrite,
    TData: AsRef<[u8]>,
{
    type Item = TSocket;
    type Error = std::io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match mem::replace(self, WriteOneInner::Poisoned) {
                WriteOneInner::WriteLen(mut inner, data) => match inner.poll()? {
                    Async::Ready((socket, _)) => {
                        *self = WriteOneInner::Write(io::write_all(socket, data));
                    }
                    Async::NotReady => {
                        *self = WriteOneInner::WriteLen(inner, data);
                    }
                },
                WriteOneInner::Write(mut inner) => match inner.poll()? {
                    Async::Ready((socket, _)) => {
                        *self = WriteOneInner::Shutdown(tokio_io::io::shutdown(socket));
                    }
                    Async::NotReady => {
                        *self = WriteOneInner::Write(inner);
                    }
                },
                WriteOneInner::Shutdown(ref mut inner) => {
                    let socket = try_ready!(inner.poll());
                    return Ok(Async::Ready(socket));
                }
                WriteOneInner::Poisoned => panic!(),
            }
        }
    }
}

/// Builds a buffer that contains the given integer encoded as variable-length.
fn build_int_buffer(num: usize) -> io::Window<[u8; 10]> {
    let mut len_data = unsigned_varint::encode::u64_buffer();
    let encoded_len = unsigned_varint::encode::u64(num as u64, &mut len_data).len();
    let mut len_data = io::Window::new(len_data);
    len_data.set_end(encoded_len);
    len_data
}

/// Future that makes `write_one` work.
struct WriteOne<TSocket, TData = Vec<u8>> {
    inner: WriteOneInner<TSocket, TData>,
}

impl<TSocket, TData> Future for WriteOne<TSocket, TData>
where
    TSocket: AsyncWrite,
    TData: AsRef<[u8]>,
{
    type Item = ();
    type Error = std::io::Error;

    #[inline]
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        Ok(self.inner.poll()?.map(|_socket| ()))
    }
}
