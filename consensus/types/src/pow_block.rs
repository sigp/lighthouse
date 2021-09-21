use crate::*;

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(Default, Debug, PartialEq, Clone)]
pub struct PowBlock {
    pub block_hash: Hash256,
    pub parent_hash: Hash256,
    pub total_difficulty: Uint256,
    pub difficulty: Uint256,
    // needed to unify with other parts of codebase
    pub timestamp: u64,
    pub block_number: u64,
}
