pub mod cached_tree_hash;
pub mod signed_root;
pub mod standard_tree_hash;

pub const BYTES_PER_CHUNK: usize = 32;
pub const HASHSIZE: usize = 32;
pub const MERKLE_HASH_CHUNCK: usize = 2 * BYTES_PER_CHUNK;

pub use cached_tree_hash::{BTreeOverlay, CachedTreeHashSubTree, Error, TreeHashCache};
pub use signed_root::SignedRoot;
pub use standard_tree_hash::{merkle_root, TreeHash};

#[derive(Debug, PartialEq, Clone)]
pub enum TreeHashType {
    Basic,
    Vector,
    List,
    Container,
}

fn num_sanitized_leaves(num_bytes: usize) -> usize {
    let leaves = (num_bytes + HASHSIZE - 1) / HASHSIZE;
    leaves.next_power_of_two()
}

fn num_nodes(num_leaves: usize) -> usize {
    2 * num_leaves - 1
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
                tree_hash::merkle_root(&ssz::ssz_encode(self))
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
