use super::*;
use ethereum_types::H256;
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

            #[allow(clippy::cast_lossless)]
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

macro_rules! impl_for_u8_array {
    ($len: expr) => {
        impl TreeHash for [u8; $len] {
            fn tree_hash_type() -> TreeHashType {
                TreeHashType::Vector
            }

            fn tree_hash_packed_encoding(&self) -> Vec<u8> {
                unreachable!("bytesN should never be packed.")
            }

            fn tree_hash_packing_factor() -> usize {
                unreachable!("bytesN should never be packed.")
            }

            fn tree_hash_root(&self) -> Vec<u8> {
                merkle_root(&self[..], 0)
            }
        }
    };
}

impl_for_u8_array!(4);
impl_for_u8_array!(32);

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
        merkle_root(&self.as_bytes().to_vec(), 0)
    }
}

// TODO: this implementation always panics, it only exists to allow us to compile whilst
// refactoring tree hash. Should be removed.
macro_rules! impl_for_list {
    ($type: ty) => {
        impl<T> TreeHash for $type
        where
            T: TreeHash,
        {
            fn tree_hash_type() -> TreeHashType {
                unimplemented!("TreeHash is not implemented for Vec or slice")
            }

            fn tree_hash_packed_encoding(&self) -> Vec<u8> {
                unimplemented!("TreeHash is not implemented for Vec or slice")
            }

            fn tree_hash_packing_factor() -> usize {
                unimplemented!("TreeHash is not implemented for Vec or slice")
            }

            fn tree_hash_root(&self) -> Vec<u8> {
                unimplemented!("TreeHash is not implemented for Vec or slice")
            }
        }
    };
}

impl_for_list!(Vec<T>);
impl_for_list!(&[T]);

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
