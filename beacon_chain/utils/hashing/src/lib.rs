extern crate tiny_keccak;

use tiny_keccak::Keccak;

pub fn canonical_hash(input: &[u8]) -> Vec<u8> {
    let mut keccak = Keccak::new_keccak256();
    keccak.update(input);
    let mut result = Vec::with_capacity(32);
    keccak.finalize(result.as_mut_slice());
    result
}
