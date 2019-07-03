pub mod cache;
pub mod error;
pub mod field;
pub mod partial;

use tree_hash::BYTES_PER_CHUNK;

pub type NodeIndex = u64;

/// A serializable represenation of a merkle proof
#[derive(Clone, Debug, Default)]
pub struct SerializedPartial {
    indices: Vec<NodeIndex>,
    chunks: Vec<u8>, // vec<bytes32>
}

impl PartialEq for SerializedPartial {
    fn eq(&self, other: &Self) -> bool {
        if self.indices.len() != other.indices.len() || self.chunks.len() != other.chunks.len() {
            return false;
        }

        self.indices.iter().enumerate().fold(true, |s, (i, j)| {
            let chunk = self.chunks[i * BYTES_PER_CHUNK];

            if let Some(other_index) = other.indices.iter().position(|e| e == j) {
                let other_chunk = other.chunks[other_index * BYTES_PER_CHUNK];
                return s && chunk == other_chunk;
            }

            false
        })
    }
}

#[macro_export]
macro_rules! vec_to_array {
    ($vec:expr, $array_size:literal) => {{
        let mut array = [0; $array_size];
        let bytes = &$vec[..array.len()];
        array.copy_from_slice(bytes);
        array
    }};
}
