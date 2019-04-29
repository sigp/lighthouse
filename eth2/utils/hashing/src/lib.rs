use ring::digest::{digest, SHA256};

pub fn hash(input: &[u8]) -> Vec<u8> {
    digest(&SHA256, input).as_ref().into()
}

/// Get merkle root of some hashed values - the input leaf nodes is expected to already be hashed
/// Outputs a `Vec<u8>` byte array of the merkle root given a set of leaf node values.
pub fn merkle_root(values: &[Vec<u8>]) -> Option<Vec<u8>> {
    let values_len = values.len();

    // check size of vector > 0 and ^ 2
    if values.is_empty() || !values_len.is_power_of_two() {
        return None;
    }

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
    return Some(o[1].clone());
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::test;

    #[test]
    fn test_hashing() {
        let input: Vec<u8> = b"hello world".as_ref().into();

        let output = hash(input.as_ref());
        let expected_hex = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        let expected: Vec<u8> = test::from_hex(expected_hex).unwrap();
        assert_eq!(expected, output);
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

        assert_eq!(&expected[..], output.unwrap().as_slice());
    }
    #[test]
    fn test_empty_input_merkle_root() {
        let input = vec![];
        let output = merkle_root(&input[..]);
        assert_eq!(None, output);
    }
    #[test]
    fn test_odd_leaf_merkle_root() {
        let input = vec![
            hash("a".as_bytes()),
            hash("b".as_bytes()),
            hash("a".as_bytes()),
        ];
        let output = merkle_root(&input[..]);
        assert_eq!(None, output);
    }
}
