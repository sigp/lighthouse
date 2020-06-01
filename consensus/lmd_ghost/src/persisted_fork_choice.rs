use ssz_derive::{Decode, Encode};
use types::Hash256;

#[derive(Encode, Decode, Clone)]
pub struct PersistedForkChoice {
    pub(crate) fc_store_bytes: Vec<u8>,
    pub(crate) proto_array_bytes: Vec<u8>,
    pub(crate) genesis_block_root: Hash256,
}
