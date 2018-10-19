extern crate blake2_rfc;

use self::blake2_rfc::blake2b::blake2b;

pub fn canonical_hash(input: &[u8]) -> Vec<u8> {
    let result = blake2b(64, &[], input);
    result.as_bytes()[0..32].to_vec()
}

pub fn proof_of_possession_hash(input: &[u8]) -> Vec<u8> {
    let result = blake2b(64, &[], input);
    let mut hash = result.as_bytes()[32..64].to_vec();
    // TODO: this padding is not part of the spec, it is required otherwise Milagro will panic.
    // We should either drop the padding or ensure the padding is in the spec.
    hash.append(&mut vec![0; 18]);
    hash
}
