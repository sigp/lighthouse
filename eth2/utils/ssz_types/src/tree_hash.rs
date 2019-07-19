use tree_hash::{merkle_root, TreeHash, TreeHashType, BYTES_PER_CHUNK};
use typenum::Unsigned;

/// A helper function providing common functionality between the `TreeHash` implementations for
/// `FixedVector` and `VariableList`.
pub fn vec_tree_hash_root<T, N>(vec: &[T]) -> Vec<u8>
where
    T: TreeHash,
    N: Unsigned,
{
    let (leaves, minimum_chunk_count) = match T::tree_hash_type() {
        TreeHashType::Basic => {
            let mut leaves =
                Vec::with_capacity((BYTES_PER_CHUNK / T::tree_hash_packing_factor()) * vec.len());

            for item in vec {
                leaves.append(&mut item.tree_hash_packed_encoding());
            }

            let values_per_chunk = T::tree_hash_packing_factor();
            let minimum_chunk_count = (N::to_usize() + values_per_chunk - 1) / values_per_chunk;

            (leaves, minimum_chunk_count)
        }
        TreeHashType::Container | TreeHashType::List | TreeHashType::Vector => {
            let mut leaves = Vec::with_capacity(vec.len() * BYTES_PER_CHUNK);

            for item in vec {
                leaves.append(&mut item.tree_hash_root())
            }

            let minimum_chunk_count = N::to_usize();

            (leaves, minimum_chunk_count)
        }
    };

    merkle_root(&leaves, minimum_chunk_count)
}

/// A helper function providing common functionality for finding the Merkle root of some bytes that
/// represent a bitfield.
pub fn bitfield_bytes_tree_hash_root<N: Unsigned>(bytes: &[u8]) -> Vec<u8> {
    let byte_size = (N::to_usize() + 7) / 8;
    let minimum_chunk_count = (byte_size + BYTES_PER_CHUNK - 1) / BYTES_PER_CHUNK;

    merkle_root(bytes, minimum_chunk_count)
}
