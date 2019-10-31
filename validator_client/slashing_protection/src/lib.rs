mod attester_slashings;
mod proposer_slashings;
mod slashing_protection;

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
        pub insert_index: usize, // index at which the new SignedAttestation should get inserted in the history
        pub reason: ValidityReason, // Used to check if the attestation is a SameVote, in which case it should not get inserted
    }
}
