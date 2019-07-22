use super::NodeIndex;
use crate::path::Path;

#[derive(Debug, PartialEq)]
pub enum Error {
    // The node is not equal to h(left, right)
    InvalidNode(NodeIndex),
    // Invalid path element
    InvalidPath(Path),
    // The partial is incomplete
    MissingNode(NodeIndex),
    // The path accesses an unintialized element
    IndexOutOfBounds(usize),
    // Only chunks that were loaded by `load_partial` can be updated
    ChunkNotLoaded(NodeIndex),
    // Only leaf nodes can be updated
    NotLeaf(NodeIndex),
    // Path provided was empty
    EmptyPath(),
}

pub type Result<T> = std::result::Result<T, Error>;
