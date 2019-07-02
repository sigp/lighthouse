use super::NodeIndex;

#[derive(Debug, PartialEq)]
pub enum Error {
    // The node is not equal to h(left, right)
    InvalidNode(NodeIndex),
    // Invalid path element
    InvalidPath(String),
    // The partial is incomplete
    MissingNode(NodeIndex),
}

pub type Result<T> = std::result::Result<T, Error>;
