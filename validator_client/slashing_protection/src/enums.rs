use crate::attester_slashings::InvalidAttestation;
use crate::proposer_slashings::InvalidBlock;

#[derive(PartialEq, Debug)]
pub enum NotSafe {
    InvalidAttestation(InvalidAttestation),
    InvalidBlock(InvalidBlock),
    PruningError,
}

#[derive(PartialEq, Debug)]
pub enum ValidData {
    EmptyHistory,
    SameVote,
    Valid,
}

#[derive(PartialEq, Debug)]
pub struct Safe {
    pub insert_index: usize,
    pub reason: ValidData,
}
