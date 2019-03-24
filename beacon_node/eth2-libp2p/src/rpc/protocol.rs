use super::methods::*;
use libp2p::core::{upgrade, InboundUpgrade, OutboundUpgrade, UpgradeInfo};
use ssz::{ssz_encode, Decodable, Encodable, SszStream};
use std::io;
use std::iter;
use tokio::io::{AsyncRead, AsyncWrite};

/// The maximum bytes that can be sent across the RPC.
const MAX_READ_SIZE: usize = 4_194_304; // 4M

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
pub enum RPCEvent {
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

impl UpgradeInfo for RPCEvent {
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
    type Output = RPCEvent;
    type Error = DecodeError;
    type Future =
        upgrade::ReadOneThen<TSocket, (), fn(Vec<u8>, ()) -> Result<RPCEvent, DecodeError>>;

    fn upgrade_inbound(self, socket: TSocket, _: Self::Info) -> Self::Future {
        upgrade::read_one_then(socket, MAX_READ_SIZE, (), |packet, ()| Ok(decode(packet)?))
    }
}

fn decode(packet: Vec<u8>) -> Result<RPCEvent, DecodeError> {
    // decode the header of the rpc
    // request/response
    let (request, index) = bool::ssz_decode(&packet, 0)?;
    let (id, index) = u64::ssz_decode(&packet, index)?;
    let (method_id, index) = u16::ssz_decode(&packet, index)?;

    if request {
        let body = match RPCMethod::from(method_id) {
            RPCMethod::Hello => {
                let (hello_body, _index) = HelloMessage::ssz_decode(&packet, index)?;
                RPCRequest::Hello(hello_body)
            }
            RPCMethod::Goodbye => {
                let (goodbye_reason, _index) = GoodbyeReason::ssz_decode(&packet, index)?;
                RPCRequest::Goodbye(goodbye_reason)
            }
            RPCMethod::BeaconBlockRoots => {
                let (block_roots_request, _index) =
                    BeaconBlockRootsRequest::ssz_decode(&packet, index)?;
                RPCRequest::BeaconBlockRoots(block_roots_request)
            }
            RPCMethod::BeaconBlockHeaders => {
                let (block_headers_request, _index) =
                    BeaconBlockHeadersRequest::ssz_decode(&packet, index)?;
                RPCRequest::BeaconBlockHeaders(block_headers_request)
            }
            RPCMethod::BeaconBlockBodies => {
                let (block_bodies_request, _index) =
                    BeaconBlockBodiesRequest::ssz_decode(&packet, index)?;
                RPCRequest::BeaconBlockBodies(block_bodies_request)
            }
            RPCMethod::BeaconChainState => {
                let (chain_state_request, _index) =
                    BeaconChainStateRequest::ssz_decode(&packet, index)?;
                RPCRequest::BeaconChainState(chain_state_request)
            }
            RPCMethod::Unknown => return Err(DecodeError::UnknownRPCMethod),
        };

        Ok(RPCEvent::Request {
            id,
            method_id,
            body,
        })
    }
    // we have received a response
    else {
        let result = match RPCMethod::from(method_id) {
            RPCMethod::Hello => {
                let (body, _index) = HelloMessage::ssz_decode(&packet, index)?;
                RPCResponse::Hello(body)
            }
            RPCMethod::Goodbye => unreachable!("Should never receive a goodbye response"),
            RPCMethod::BeaconBlockRoots => {
                let (body, _index) = BeaconBlockRootsResponse::ssz_decode(&packet, index)?;
                RPCResponse::BeaconBlockRoots(body)
            }
            RPCMethod::BeaconBlockHeaders => {
                let (body, _index) = BeaconBlockHeadersResponse::ssz_decode(&packet, index)?;
                RPCResponse::BeaconBlockHeaders(body)
            }
            RPCMethod::BeaconBlockBodies => {
                let (body, _index) = BeaconBlockBodiesResponse::ssz_decode(&packet, index)?;
                RPCResponse::BeaconBlockBodies(body)
            }
            RPCMethod::BeaconChainState => {
                let (body, _index) = BeaconChainStateResponse::ssz_decode(&packet, index)?;
                RPCResponse::BeaconChainState(body)
            }
            RPCMethod::Unknown => return Err(DecodeError::UnknownRPCMethod),
        };
        Ok(RPCEvent::Response {
            id,
            method_id,
            result,
        })
    }
}

impl<TSocket> OutboundUpgrade<TSocket> for RPCEvent
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

impl Encodable for RPCEvent {
    fn ssz_append(&self, s: &mut SszStream) {
        match self {
            RPCEvent::Request {
                id,
                method_id,
                body,
            } => {
                s.append(&true);
                s.append(id);
                s.append(method_id);
                match body {
                    RPCRequest::Hello(body) => {
                        s.append(body);
                    }
                    RPCRequest::Goodbye(body) => {
                        s.append(body);
                    }
                    RPCRequest::BeaconBlockRoots(body) => {
                        s.append(body);
                    }
                    RPCRequest::BeaconBlockHeaders(body) => {
                        s.append(body);
                    }
                    RPCRequest::BeaconBlockBodies(body) => {
                        s.append(body);
                    }
                    RPCRequest::BeaconChainState(body) => {
                        s.append(body);
                    }
                }
            }
            RPCEvent::Response {
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
                    RPCResponse::BeaconBlockRoots(response) => {
                        s.append(response);
                    }
                    RPCResponse::BeaconBlockHeaders(response) => {
                        s.append(response);
                    }
                    RPCResponse::BeaconBlockBodies(response) => {
                        s.append(response);
                    }
                    RPCResponse::BeaconChainState(response) => {
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
