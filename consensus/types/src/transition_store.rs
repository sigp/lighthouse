use crate::*;

#[cfg_attr(feature = "arbitrary-fuzz", derive(arbitrary::Arbitrary))]
#[derive(
Default, Debug, PartialEq, Clone,
)]
pub struct TransitionStore {
    pub terminal_total_difficulty: Uint256,
}

impl TransitionStore {
    fn is_valid_terminal_pow_block(&self, block: &PowBlock, parent: &PowBlock) -> bool {
        let is_total_difficulty_reached = block.total_difficulty >= self.terminal_total_difficulty;
        let is_parent_total_difficulty_valid = parent.total_difficulty < self.terminal_total_difficulty;

        is_total_difficulty_reached && is_parent_total_difficulty_valid
    }
}

