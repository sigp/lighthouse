pub mod cache;
pub mod error;
pub mod field;
pub mod partial;

pub type NodeIndex = u64;

/// A serializable represenation of a merkle proof
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SerializedPartial {
    indicies: Vec<NodeIndex>,
    chunks: Vec<u8>, // vec<bytes32>
}
