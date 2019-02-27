use tiny_keccak::Keccak;

pub fn hash(input: &[u8]) -> Vec<u8> {
    let mut keccak = Keccak::new_keccak256();
    keccak.update(input);
    let mut result = vec![0; 32];
    keccak.finalize(result.as_mut_slice());
    result
}

/// Generate Merkle Root
/// 
/// Outputs a `Vec<u8>` byte array of the merkle root given a set of leaf node values.
/// Expects leaf nodes to already be hashed.
pub fn merkle_root(values: &[Vec<u8>]) -> Vec<u8> {
    let values_len = values.len();
    
    // vector to store hashes
    // filled with 0 as placeholders
    let mut o: Vec<Vec<u8>> = vec![vec![0]; values_len];

    // append values to the end
    o.append(&mut values.to_vec());

    // traverse backwards as values are at the end
    // then fill placeholders with a hash of two leaf nodes
    for i in (0..values_len).rev() {
        let mut current_value: Vec<u8> = o[i * 2].clone();
        current_value.append(&mut o[i * 2 + 1].clone());

        o[i] = hash(&current_value[..]);
    }

    // the root hash will be at index 1
    o[1].clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::From;

    #[test]
    fn test_hashing() {
        let input: Vec<u8> = From::from("hello");

        let output = hash(input.as_ref());
        let expected = &[
            0x1c, 0x8a, 0xff, 0x95, 0x06, 0x85, 0xc2, 0xed, 0x4b, 0xc3, 0x17, 0x4f, 0x34, 0x72,
            0x28, 0x7b, 0x56, 0xd9, 0x51, 0x7b, 0x9c, 0x94, 0x81, 0x27, 0x31, 0x9a, 0x09, 0xa7,
            0xa3, 0x6d, 0xea, 0xc8,
        ];
        assert_eq!(expected, output.as_slice());
    }

    #[test]
    fn test_merkle_root() {
        // hash the leaf nodes
        let mut input = vec![
            hash("a".as_bytes()),
            hash("b".as_bytes()),
            hash("c".as_bytes()),
            hash("d".as_bytes()),
        ];

        // generate a merkle tree and return the root
        let output = merkle_root(&input[..]);

        // create merkle root manually
        let mut leaf_1_2: Vec<u8> = input[0].clone(); // a
        leaf_1_2.append(&mut input[1].clone()); // b

        let mut leaf_3_4: Vec<u8> = input[2].clone(); // c
        leaf_3_4.append(&mut input[3].clone()); // d

        let node_1 = hash(&leaf_1_2[..]);
        let node_2 = hash(&leaf_3_4[..]);

        let mut root: Vec<u8> = node_1.clone(); // ab
        root.append(&mut node_2.clone()); // cd

        let expected = hash(&root[..]);

        assert_eq!(&expected[..], output.as_slice());

    }
}
