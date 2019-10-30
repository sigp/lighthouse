mod attester_slashings;
mod history_info;
mod proposer_slashings;

mod enums {
    use crate::attester_slashings::InvalidAttestation;
    use crate::proposer_slashings::InvalidBlock;
    use std::io::ErrorKind;

    #[derive(PartialEq, Debug)]
    pub enum NotSafe {
        InvalidAttestation(InvalidAttestation),
        InvalidBlock(InvalidBlock),
        PruningError,
        IOError(ErrorKind),
    }

    #[derive(PartialEq, Debug)]
    pub enum ValidityReason {
        EmptyHistory,
        SameVote,
        Valid,
    }

    #[derive(PartialEq, Debug)]
    pub struct Safe {
        pub insert_index: usize,
        pub reason: ValidityReason,
    }
}
