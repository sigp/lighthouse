use types::{Hash256}
use hashing::canonical_hash;

fn merkle_root(values: Vec<T>) -> Hash256 {
    let mut o = vec![0; values.len()];
    o.append(values);

    for v in &values {
        canonical_hash(v.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn calculate_merkle_root() {
        let values = vec!['abc', 'lmn', 'xyz', 'o0o'];

        let test_leaf_1 = canonical_hash(values[0]);
        let test_leaf_2 = canonical_hash(values[1]);
        let test_leaf_3 = canonical_hash(values[2]);
        let test_leaf_4 = canonical_hash(values[3]);
        let test_node_1 = canonical_hash(vec![test_leaf_4, test_leaf_3]);
        let test_node_2 = canonical_hash(vec![test_leaf_2, test_leaf_1]);
        let test_root   = canonical_hash(vec![test_node_1, test_node_2]);

        let result      = merkle_root(values);
        assert_eq!(result, test_root);
    }
}
