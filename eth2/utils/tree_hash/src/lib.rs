pub mod impls;
mod merkle_stream;
mod merkleize_padded;
mod merkleize_standard;

pub use merkle_stream::MerkleStream;
pub use merkleize_padded::merkleize_padded;
pub use merkleize_standard::merkleize_standard;

use eth2_hashing::{ZERO_HASHES, ZERO_HASHES_MAX_INDEX};

pub const BYTES_PER_CHUNK: usize = 32;
pub const HASHSIZE: usize = 32;
pub const MERKLE_HASH_CHUNK: usize = 2 * BYTES_PER_CHUNK;

pub type Hash256 = ethereum_types::H256;

/// Alias to `merkleize_padded(&bytes, minimum_chunk_count)`
///
/// If `minimum_chunk_count < bytes / BYTES_PER_CHUNK`, padding will be added for the difference
/// between the two.
pub fn merkle_root(bytes: &[u8], minimum_chunk_count: usize) -> Hash256 {
    merkleize_padded(&bytes, minimum_chunk_count)
}

/// Returns the node created by hashing `root` and `length`.
///
/// Used in `TreeHash` for inserting the length of a list above it's root.
pub fn mix_in_length(root: &Hash256, length: usize) -> Hash256 {
    let usize_len = std::mem::size_of::<usize>();

    let mut length_bytes = [0; BYTES_PER_CHUNK];
    length_bytes[0..usize_len].copy_from_slice(&length.to_le_bytes());

    Hash256::from_slice(&eth2_hashing::hash32_concat(root.as_bytes(), &length_bytes)[..])
}

/// Returns a cached padding node for a given height.
fn get_zero_hash(height: usize) -> &'static [u8] {
    if height <= ZERO_HASHES_MAX_INDEX {
        &ZERO_HASHES[height]
    } else {
        panic!("Tree exceeds MAX_TREE_DEPTH of {}", ZERO_HASHES_MAX_INDEX)
    }
}

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

    fn tree_hash_root(&self) -> Hash256;
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn mix_length() {
        let hash = {
            let mut preimage = vec![42; BYTES_PER_CHUNK];
            preimage.append(&mut vec![42]);
            preimage.append(&mut vec![0; BYTES_PER_CHUNK - 1]);
            eth2_hashing::hash(&preimage)
        };

        assert_eq!(
            mix_in_length(&Hash256::from_slice(&[42; BYTES_PER_CHUNK]), 42).as_bytes(),
            &hash[..]
        );
    }
}
