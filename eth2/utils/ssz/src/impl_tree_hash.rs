use super::ethereum_types::{Address, H256};
use super::{hash, merkle_hash, ssz_encode, TreeHash};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_impl_tree_hash_vec() {
        let result = vec![1u32, 2, 3, 4, 5, 6, 7].hash_tree_root();
        assert_eq!(result.len(), 32);
    }
}
