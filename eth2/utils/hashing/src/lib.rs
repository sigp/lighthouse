use tiny_keccak::Keccak;

pub fn canonical_hash(input: &[u8]) -> Vec<u8> {
    let mut keccak = Keccak::new_keccak256();
    keccak.update(input);
    let mut result = vec![0; 32];
    keccak.finalize(result.as_mut_slice());
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::From;

    #[test]
    fn test_hashing() {
        let input: Vec<u8> = From::from("hello");

        let output = canonical_hash(input.as_ref());
        let expected = &[
            0x1c, 0x8a, 0xff, 0x95, 0x06, 0x85, 0xc2, 0xed, 0x4b, 0xc3, 0x17, 0x4f, 0x34, 0x72,
            0x28, 0x7b, 0x56, 0xd9, 0x51, 0x7b, 0x9c, 0x94, 0x81, 0x27, 0x31, 0x9a, 0x09, 0xa7,
            0xa3, 0x6d, 0xea, 0xc8,
        ];
        assert_eq!(expected, output.as_slice());
    }
}
