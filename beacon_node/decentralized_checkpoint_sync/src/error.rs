use crate::LightClientStoreSchema;
use types::{ForkName, Hash256};

/// An error produced while validating light-client data for checkpoint sync.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum LightClientSyncError {
    #[error("light-client sync is unsupported for fork {0}")]
    UnsupportedFork(ForkName),

    #[error("light-client header variant {actual} does not match data fork {expected}")]
    HeaderVariantMismatch {
        expected: ForkName,
        actual: ForkName,
    },

    #[error("light-client data fork {data_fork} predates beacon header fork {beacon_header_fork}")]
    DataForkBeforeBeaconHeaderFork {
        data_fork: ForkName,
        beacon_header_fork: ForkName,
    },

    #[error("pre-Capella light-client header has a non-default execution payload")]
    NonDefaultExecutionPayload,

    #[error("pre-Capella light-client header has a non-default execution branch")]
    NonDefaultExecutionBranch,

    #[error("pre-Deneb light-client header has non-zero blob gas fields")]
    NonZeroBlobGasFields,

    #[error("light-client header has an invalid execution payload proof")]
    InvalidExecutionPayloadProof,

    #[error("bootstrap schema {bootstrap_schema:?} is newer than store schema {store_schema:?}")]
    IncompatibleStoreSchema {
        bootstrap_schema: LightClientStoreSchema,
        store_schema: LightClientStoreSchema,
    },

    #[error("bootstrap beacon root {actual:?} does not match trusted block root {expected:?}")]
    BootstrapRootMismatch { expected: Hash256, actual: Hash256 },

    #[error("bootstrap current sync committee proof is invalid")]
    InvalidCurrentSyncCommitteeProof,
}
