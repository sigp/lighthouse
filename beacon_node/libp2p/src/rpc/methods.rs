/// Available RPC methods types and ids.
use ssz_derive::{Decode, Encode};
use types::{Epoch, Hash256, Slot};

#[derive(Debug)]
pub enum RPCMethod {
    Hello,
    Unknown,
}

impl From<u16> for RPCMethod {
    fn from(method_id: u16) -> Self {
        match method_id {
            0 => RPCMethod::Hello,
            _ => RPCMethod::Unknown,
        }
    }
}

impl Into<u16> for RPCMethod {
    fn into(self) -> u16 {
        match self {
            RPCMethod::Hello => 0,
            _ => 0,
        }
    }
}

#[derive(Debug, Clone)]
pub enum RPCRequest {
    Hello(HelloMessage),
}

#[derive(Debug, Clone)]
pub enum RPCResponse {
    Hello(HelloMessage),
}

// request/response structs for RPC methods
#[derive(Encode, Decode, Clone, Debug)]
pub struct HelloMessage {
    pub network_id: u8,
    pub latest_finalized_root: Hash256,
    pub latest_finalized_epoch: Epoch,
    pub best_root: Hash256,
    pub best_slot: Slot,
}
