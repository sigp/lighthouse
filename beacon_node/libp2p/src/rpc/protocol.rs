use super::methods::{HelloBody, RPCMethod, RPCRequest, RPCResponse};
use libp2p::core::{upgrade, InboundUpgrade, OutboundUpgrade, UpgradeInfo};
use ssz::{ssz_encode, Decodable, Encodable, SszStream};
use std::io;
use std::iter;
use tokio::io::{AsyncRead, AsyncWrite};

/// The maximum bytes that can be sent across the RPC.
const MAX_READ_SIZE: usize = 2048;

/// Implementation of the `ConnectionUpgrade` for the rpc protocol.

#[derive(Debug, Clone)]
pub struct RPCProtocol;

impl UpgradeInfo for RPCProtocol {
    type Info = &'static [u8];
    type InfoIter = iter::Once<Self::Info>;

    #[inline]
    fn protocol_info(&self) -> Self::InfoIter {
        iter::once(b"/eth/serenity/rpc/1.0.0")
    }
}

impl Default for RPCProtocol {
    fn default() -> Self {
        RPCProtocol
    }
}

/// The RPC types which are sent/received in this protocol.
#[derive(Debug, Clone)]
pub enum RpcEvent {
    Request {
        id: u64,
        method_id: u16,
        body: RPCRequest,
    },
    Response {
        id: u64,
        method_id: u16, //TODO: Remove and process decoding upstream
        result: RPCResponse,
    },
}

impl UpgradeInfo for RpcEvent {
    type Info = &'static [u8];
    type InfoIter = iter::Once<Self::Info>;

    #[inline]
    fn protocol_info(&self) -> Self::InfoIter {
        iter::once(b"/eth/serenity/rpc/1.0.0")
    }
}

impl<TSocket> InboundUpgrade<TSocket> for RPCProtocol
where
    TSocket: AsyncRead + AsyncWrite,
{
    type Output = RpcEvent;
    type Error = DecodeError;
    type Future =
        upgrade::ReadOneThen<TSocket, (), fn(Vec<u8>, ()) -> Result<RpcEvent, DecodeError>>;

    fn upgrade_inbound(self, socket: TSocket, _: Self::Info) -> Self::Future {
        upgrade::read_one_then(socket, MAX_READ_SIZE, (), |packet, ()| Ok(decode(packet)?))
    }
}

fn decode(packet: Vec<u8>) -> Result<RpcEvent, DecodeError> {
    // decode the header of the rpc
    // request/response
    let (request, index) = bool::ssz_decode(&packet, 0)?;
    let (id, index) = u64::ssz_decode(&packet, index)?;
    let (method_id, index) = u16::ssz_decode(&packet, index)?;

    if request {
        let body = match RPCMethod::from(method_id) {
            RPCMethod::Hello => {
                let (hello_body, _index) = HelloBody::ssz_decode(&packet, index)?;
                RPCRequest::Hello(hello_body)
            }
            RPCMethod::Unknown => return Err(DecodeError::UnknownRPCMethod),
        };

        return Ok(RpcEvent::Request {
            id,
            method_id,
            body,
        });
    }
    // we have received a response
    else {
        let result = match RPCMethod::from(method_id) {
            RPCMethod::Hello => {
                let (body, _index) = HelloBody::ssz_decode(&packet, index)?;
                RPCResponse::Hello(body)
            }
            RPCMethod::Unknown => return Err(DecodeError::UnknownRPCMethod),
        };
        return Ok(RpcEvent::Response {
            id,
            method_id,
            result,
        });
    }
}

impl<TSocket> OutboundUpgrade<TSocket> for RpcEvent
where
    TSocket: AsyncWrite,
{
    type Output = ();
    type Error = io::Error;
    type Future = upgrade::WriteOne<TSocket>;

    #[inline]
    fn upgrade_outbound(self, socket: TSocket, _: Self::Info) -> Self::Future {
        let bytes = ssz_encode(&self);
        upgrade::write_one(socket, bytes)
    }
}

impl Encodable for RpcEvent {
    fn ssz_append(&self, s: &mut SszStream) {
        match self {
            RpcEvent::Request {
                id,
                method_id,
                body,
            } => {
                s.append(&true);
                s.append(id);
                s.append(method_id);
                match body {
                    RPCRequest::Hello(body) => s.append(body),
                };
            }
            RpcEvent::Response {
                id,
                method_id,
                result,
            } => {
                s.append(&false);
                s.append(id);
                s.append(method_id);
                match result {
                    RPCResponse::Hello(response) => {
                        s.append(response);
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum DecodeError {
    ReadError(upgrade::ReadOneError),
    SSZDecodeError(ssz::DecodeError),
    UnknownRPCMethod,
}

impl From<upgrade::ReadOneError> for DecodeError {
    #[inline]
    fn from(err: upgrade::ReadOneError) -> Self {
        DecodeError::ReadError(err)
    }
}

impl From<ssz::DecodeError> for DecodeError {
    #[inline]
    fn from(err: ssz::DecodeError) -> Self {
        DecodeError::SSZDecodeError(err)
    }
}
