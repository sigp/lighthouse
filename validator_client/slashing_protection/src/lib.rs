mod attester_slashings;
mod proposer_slashings;
mod slashing_protection;

mod enums {
    use crate::attester_slashings::InvalidAttestation;
    use crate::proposer_slashings::InvalidBlock;
    use ssz::DecodeError;
    use std::io::{Error as IOError, ErrorKind};

    impl From<IOError> for NotSafe {
        fn from(error: IOError) -> NotSafe {
            NotSafe::IOError(error.kind())
        }
    }

    impl From<DecodeError> for NotSafe {
        fn from(error: DecodeError) -> NotSafe {
            NotSafe::DecodeError(error)
        }
    }

    #[derive(PartialEq, Debug)]
    pub enum NotSafe {
        InvalidAttestation(InvalidAttestation),
        InvalidBlock(InvalidBlock),
        PruningError,
        IOError(ErrorKind),
        DecodeError(DecodeError),
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
