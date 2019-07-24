use super::{NodeIndex, BYTES_PER_CHUNK};
use ssz_derive::{Decode, Encode};

/// A serializable represenation of a `Partial`.
#[derive(Clone, Debug, Decode, Encode, Default)]
pub struct SerializedPartial {
    pub indices: Vec<NodeIndex>,
    pub chunks: Vec<u8>, // vec<bytes32>
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
