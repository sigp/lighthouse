use tree_hash::TreeHashType;

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    ShouldNotProduceBTreeOverlay,
    NoFirstNode,
    NoBytesForRoot,
    UnableToObtainSlices,
    UnableToGrowMerkleTree,
    UnableToShrinkMerkleTree,
    TreeCannotHaveZeroNodes,
    ShouldNeverBePacked(TreeHashType),
    BytesAreNotEvenChunks(usize),
    NoModifiedFieldForChunk(usize),
    NoBytesForChunk(usize),
    NoSchemaForIndex(usize),
    NotLeafNode(usize),
}
