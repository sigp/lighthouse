use super::NodeIndex;
use crate::path::Path;

/// An enum of errors that can occur when interacting with partial.
#[derive(Debug, PartialEq)]
pub enum Error {
    // Invalid path element
    InvalidPath(Path),
    // The path accesses an unintialized element
    IndexOutOfBounds(u64),
    // Missing chunk
    ChunkNotLoaded(NodeIndex),
    // Path provided was empty
    EmptyPath(),
}

pub type Result<T> = std::result::Result<T, Error>;
