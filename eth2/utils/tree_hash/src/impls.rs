use super::*;
use crate::merkleize::merkle_root;
use ethereum_types::H256;
use hashing::hash;
use int_to_bytes::int_to_bytes32;

macro_rules! impl_for_bitsize {
    ($type: ident, $bit_size: expr) => {
        impl TreeHash for $type {
            fn tree_hash_type() -> TreeHashType {
                TreeHashType::Basic
            }

            fn tree_hash_packed_encoding(&self) -> Vec<u8> {
                self.to_le_bytes().to_vec()
            }

            fn tree_hash_packing_factor() -> usize {
                HASHSIZE / ($bit_size / 8)
            }

            fn tree_hash_root(&self) -> Vec<u8> {
                int_to_bytes32(*self as u64)
            }
        }
    };
}

impl_for_bitsize!(u8, 8);
impl_for_bitsize!(u16, 16);
impl_for_bitsize!(u32, 32);
impl_for_bitsize!(u64, 64);
impl_for_bitsize!(usize, 64);

impl TreeHash for bool {
    fn tree_hash_type() -> TreeHashType {
        TreeHashType::Basic
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        (*self as u8).tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        u8::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> Vec<u8> {
        int_to_bytes32(*self as u64)
    }
}

impl TreeHash for [u8; 4] {
    fn tree_hash_type() -> TreeHashType {
        TreeHashType::List
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("bytesN should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("bytesN should never be packed.")
    }

    fn tree_hash_root(&self) -> Vec<u8> {
        merkle_root(&self[..])
    }
}

impl TreeHash for H256 {
    fn tree_hash_type() -> TreeHashType {
        TreeHashType::Vector
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    fn tree_hash_packing_factor() -> usize {
        1
    }

    fn tree_hash_root(&self) -> Vec<u8> {
        merkle_root(&self.as_bytes().to_vec())
    }
}

impl<T> TreeHash for Vec<T>
where
    T: TreeHash,
{
    fn tree_hash_type() -> TreeHashType {
        TreeHashType::List
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("List should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("List should never be packed.")
    }

    fn tree_hash_root(&self) -> Vec<u8> {
        let mut root_and_len = Vec::with_capacity(HASHSIZE * 2);
        root_and_len.append(&mut vec_tree_hash_root(self));
        root_and_len.append(&mut int_to_bytes32(self.len() as u64));

        hash(&root_and_len)
    }
}

pub fn vec_tree_hash_root<T>(vec: &[T]) -> Vec<u8>
where
    T: TreeHash,
{
    let leaves = match T::tree_hash_type() {
        TreeHashType::Basic => {
            let mut leaves =
                Vec::with_capacity((HASHSIZE / T::tree_hash_packing_factor()) * vec.len());

            for item in vec {
                leaves.append(&mut item.tree_hash_packed_encoding());
            }

            leaves
        }
        TreeHashType::Container | TreeHashType::List | TreeHashType::Vector => {
            let mut leaves = Vec::with_capacity(vec.len() * HASHSIZE);

            for item in vec {
                leaves.append(&mut item.tree_hash_root())
            }

            leaves
        }
    };

    merkle_root(&leaves)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn bool() {
        let mut true_bytes: Vec<u8> = vec![1];
        true_bytes.append(&mut vec![0; 31]);

        let false_bytes: Vec<u8> = vec![0; 32];

        assert_eq!(true.tree_hash_root(), true_bytes);
        assert_eq!(false.tree_hash_root(), false_bytes);
    }

}
