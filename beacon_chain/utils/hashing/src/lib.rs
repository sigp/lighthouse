extern crate blake2_rfc;

use self::blake2_rfc::blake2b::blake2b;

pub fn canonical_hash(input: &[u8]) -> Vec<u8> {
    let result = blake2b(64, &[], input);
    result.as_bytes()[0..32].to_vec()
}
