pub mod attester_slashings;
pub mod proposer_slashings;
pub mod slashing_protection;
mod utils;

pub mod enums {
    use crate::attester_slashings::InvalidAttestation;
    use crate::proposer_slashings::InvalidBlock;
    use rusqlite::Error as SQLError;
    use std::io::{Error as IOError, ErrorKind};

    impl From<IOError> for NotSafe {
        fn from(error: IOError) -> NotSafe {
            NotSafe::IOError(error.kind())
        }
    }

    impl From<SQLError> for NotSafe {
        fn from(error: SQLError) -> NotSafe {
            NotSafe::SQLError(error.to_string())
        }
    }

    #[derive(PartialEq, Debug)]
    pub enum NotSafe {
        InvalidAttestation(InvalidAttestation),
        InvalidBlock(InvalidBlock),
        PruningError,
        IOError(ErrorKind),
        SQLError(String),
    }

    #[derive(PartialEq, Debug)]
    pub enum ValidityReason {
        // History is empty so inserting is safe
        EmptyHistory,
        // Re-signing a previous vote is safe
        SameVote,
        // Incoming data is safe from slashing
        Valid,
    }

    #[derive(PartialEq, Debug)]
    pub struct Safe {
        /// Used to check if the attestation is a SameVote, in which case it should not get inserted.
        pub reason: ValidityReason,
    }
}
