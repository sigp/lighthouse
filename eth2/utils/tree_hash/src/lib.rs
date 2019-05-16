pub mod impls;
pub mod merkleize;

pub const BYTES_PER_CHUNK: usize = 32;
pub const HASHSIZE: usize = 32;
pub const MERKLE_HASH_CHUNK: usize = 2 * BYTES_PER_CHUNK;

#[derive(Debug, PartialEq, Clone)]
pub enum TreeHashType {
    Basic,
    Vector,
    List,
    Container,
}

pub trait TreeHash {
    fn tree_hash_type() -> TreeHashType;

    fn tree_hash_packed_encoding(&self) -> Vec<u8>;

    fn tree_hash_packing_factor() -> usize;

    fn tree_hash_root(&self) -> Vec<u8>;
}

pub trait SignedRoot: TreeHash {
    fn signed_root(&self) -> Vec<u8>;
}

#[macro_export]
macro_rules! tree_hash_ssz_encoding_as_vector {
    ($type: ident) => {
        impl tree_hash::TreeHash for $type {
            fn tree_hash_type() -> tree_hash::TreeHashType {
                tree_hash::TreeHashType::Vector
            }

            fn tree_hash_packed_encoding(&self) -> Vec<u8> {
                unreachable!("Vector should never be packed.")
            }

            fn tree_hash_packing_factor() -> usize {
                unreachable!("Vector should never be packed.")
            }

            fn tree_hash_root(&self) -> Vec<u8> {
                tree_hash::merkleize::merkle_root(&ssz::ssz_encode(self))
            }
        }
    };
}

#[macro_export]
macro_rules! tree_hash_ssz_encoding_as_list {
    ($type: ident) => {
        impl tree_hash::TreeHash for $type {
            fn tree_hash_type() -> tree_hash::TreeHashType {
                tree_hash::TreeHashType::List
            }

            fn tree_hash_packed_encoding(&self) -> Vec<u8> {
                unreachable!("List should never be packed.")
            }

            fn tree_hash_packing_factor() -> usize {
                unreachable!("List should never be packed.")
            }

            fn tree_hash_root(&self) -> Vec<u8> {
                ssz::ssz_encode(self).tree_hash_root()
            }
        }
    };
}
