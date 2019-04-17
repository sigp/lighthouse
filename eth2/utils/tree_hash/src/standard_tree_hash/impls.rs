use super::*;
use ethereum_types::H256;

macro_rules! impl_for_bitsize {
    ($type: ident, $bit_size: expr) => {
        impl TreeHash for $type {
            fn tree_hash_type() -> TreeHashType {
                TreeHashType::Basic
            }

            fn tree_hash_packed_encoding(&self) -> Vec<u8> {
                ssz_encode(self)
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
impl_for_bitsize!(bool, 8);

impl TreeHash for [u8; 4] {
    fn tree_hash_type() -> TreeHashType {
        TreeHashType::List
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        panic!("bytesN should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        panic!("bytesN should never be packed.")
    }

    fn tree_hash_root(&self) -> Vec<u8> {
        merkle_root(&ssz::ssz_encode(self))
    }
}

impl TreeHash for H256 {
    fn tree_hash_type() -> TreeHashType {
        TreeHashType::Vector
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        ssz_encode(self)
    }

    fn tree_hash_packing_factor() -> usize {
        1
    }

    fn tree_hash_root(&self) -> Vec<u8> {
        merkle_root(&ssz::ssz_encode(self))
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
