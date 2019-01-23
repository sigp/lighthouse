use types::{Hash256}
use hashing::canonical_hash;

pub fn merkle_root(values: Vec<T>) -> Hash256 {
    let mut o: Vec<&[u8]> = vec![0; values.len()];
    let mut value_hashes = vec![];
    for v in values {
       value_hashes.push(canonical_hash(v);
    }

    o.append(values);

    for i in (0..values.len() - 1).rev() {
        canonical_hash(o[i * 2] + o[i * 2 + 1]);
    }

    o[1];
}

#[cfg(test)]
mod tests {
    #[test]
    fn calculate_merkle_root() {
        let values = vec!["abc", "lmn", "xyz", "o0o"];

        let test_leaf_0 = canonical_hash(values[0]);
        let test_leaf_1 = canonical_hash(values[1]);
        let test_leaf_2 = canonical_hash(values[2]);
        let test_leaf_3 = canonical_hash(values[3]);
        let test_node_0 = canonical_hash(test_leaf_3 + test_leaf_2);
        let test_node_1 = canonical_hash(test_leaf_1 + test_leaf_0);
        let test_root   = canonical_hash(test_node_0 + test_node_0);

        let result      = merkle_root(values);
        assert_eq!(result, test_root);
    }
}
