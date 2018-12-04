extern crate blake2_rfc;

use self::blake2_rfc::blake2b::blake2b;

use super::ethereum_types::{Address, H256};
use super::{ssz_encode, TreeHash};

// I haven't added tests for tree_hash implementations that simply pass
// thru to the szz_encode lib for which tests already exist. Do we want
// test anyway?

impl TreeHash for u8 {
    fn tree_hash(&self) -> Vec<u8> {
        ssz_encode(self)
    }
}

impl TreeHash for u16 {
    fn tree_hash(&self) -> Vec<u8> {
        ssz_encode(self)
    }
}

impl TreeHash for u32 {
    fn tree_hash(&self) -> Vec<u8> {
        ssz_encode(self)
    }
}

impl TreeHash for u64 {
    fn tree_hash(&self) -> Vec<u8> {
        ssz_encode(self)
    }
}

impl TreeHash for Address {
    fn tree_hash(&self) -> Vec<u8> {
        ssz_encode(self)
    }
}

impl TreeHash for H256 {
    fn tree_hash(&self) -> Vec<u8> {
        ssz_encode(self)
    }
}

// hash byte arrays
impl TreeHash for [u8] {
    fn tree_hash(&self) -> Vec<u8> {
        hash(&self)
    }
}

/**
 * From the Spec:
 *      We define hash(x) as BLAKE2b-512(x)[0:32]
 * From the python sample code:
 *      return blake2b(x).digest()[:32]
 *
 * This was orginally writting for blake2s before it was changed to blake2b
 * Perhaps, we should be using 'canonical_hash' in the hashing lib?
 */
fn hash(data: &[u8]) -> Vec<u8> {
    let result = blake2b(32, &[], &data);
    result.as_bytes().to_vec()
}
