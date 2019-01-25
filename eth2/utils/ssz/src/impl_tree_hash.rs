use super::ethereum_types::{Address, H256};
use super::{hash, merkle_hash, ssz_encode, TreeHash};
use std::collections::HashMap;

impl TreeHash for u8 {
    fn hash_tree_root(&self) -> Vec<u8> {
        ssz_encode(self)
    }
}

impl TreeHash for u16 {
    fn hash_tree_root(&self) -> Vec<u8> {
        ssz_encode(self)
    }
}

impl TreeHash for u32 {
    fn hash_tree_root(&self) -> Vec<u8> {
        ssz_encode(self)
    }
}

impl TreeHash for u64 {
    fn hash_tree_root(&self) -> Vec<u8> {
        ssz_encode(self)
    }
}

impl TreeHash for usize {
    fn hash_tree_root(&self) -> Vec<u8> {
        ssz_encode(self)
    }
}

impl TreeHash for Address {
    fn hash_tree_root(&self) -> Vec<u8> {
        ssz_encode(self)
    }
}

impl TreeHash for H256 {
    fn hash_tree_root(&self) -> Vec<u8> {
        ssz_encode(self)
    }
}

impl TreeHash for [u8] {
    fn hash_tree_root(&self) -> Vec<u8> {
        if self.len() > 32 {
            return hash(&self);
        }
        self.to_vec()
    }
}

impl<T> TreeHash for Vec<T>
where
    T: TreeHash,
{
    /// Returns the merkle_hash of a list of hash_tree_root values created
    /// from the given list.
    /// Note: A byte vector, Vec<u8>, must be converted to a slice (as_slice())
    ///       to be handled properly (i.e. hashed) as byte array.
    fn hash_tree_root(&self) -> Vec<u8> {
        let mut tree_hashes = self.iter().map(|x| x.hash_tree_root()).collect();
        merkle_hash(&mut tree_hashes)
    }
}

impl<K, V> TreeHash for HashMap<K, V>
where
    K: Eq,
    K: Hash,
    K: Ord,
    V: TreeHash,
{
    /// Appends the tree_hash for each value of 'self, sorted by key,
    /// into a byte array and returns the hash of said byte array
    fn tree_hash(&self) -> Vec<u8> {
        let mut items: Vec<_> = self.iter().collect();
        items.sort_by(|a, b| a.0.cmp(b.0));
        let mut result = Vec::new();
        for item in items {
            result.append(&mut item.1.tree_hash());
        }

        hash(&result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_impl_tree_hash_vec() {
        let result = vec![1u32, 2, 3, 4, 5, 6, 7].tree_hash();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_impl_tree_hash_hashmap() {
        let mut map = HashMap::new();
        map.insert("c", 3);
        map.insert("b", 2);
        map.insert("g", 7);
        map.insert("d", 6);
        map.insert("e", 4);
        map.insert("a", 1u32);
        map.insert("f", 5);
        let result = map.tree_hash();

        // TODO: create tests that tie-out to an offical result
        assert_eq!(
            result,
            [
                130, 215, 165, 255, 224, 6, 144, 225, 14, 139, 67, 238, 205, 240, 20, 173, 53, 0,
                105, 62, 49, 174, 244, 160, 114, 92, 232, 11, 102, 200, 112, 24
            ]
        );
    }

}
