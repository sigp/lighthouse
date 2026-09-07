use crate::LightClientStoreSchema;
use safe_arith::ArithError;
use types::{ForkName, Hash256, Slot};

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

    #[error("update schema {update_schema:?} is newer than store schema {store_schema:?}")]
    UpdateSchemaTooNew {
        update_schema: LightClientStoreSchema,
        store_schema: LightClientStoreSchema,
    },

    #[error("sync committee has {actual} participants, requires at least {minimum}")]
    InsufficientParticipants { actual: usize, minimum: u64 },

    #[error(
        "invalid update slots: current {current_slot}, signature {signature_slot}, attested {attested_slot}, finalized {finalized_slot}"
    )]
    InvalidUpdateSlots {
        current_slot: Slot,
        signature_slot: Slot,
        attested_slot: Slot,
        finalized_slot: Slot,
    },

    #[error("signature period {signature_period} is not allowed by store period {store_period}")]
    InvalidSignaturePeriod {
        store_period: u64,
        signature_period: u64,
    },

    #[error("update advances neither the finalized slot nor knowledge of the next committee")]
    IrrelevantUpdate,

    #[error("finalized header must be default when finality is absent or its slot is genesis")]
    NonDefaultFinalizedHeader,

    #[error("next sync committee must be default when its branch is absent")]
    NonDefaultNextSyncCommittee,

    #[error("update next sync committee differs from the committee already known by the store")]
    NextSyncCommitteeMismatch,

    #[error("update finality proof is invalid")]
    InvalidFinalityProof,

    #[error("update next sync committee proof is invalid")]
    InvalidNextSyncCommitteeProof,

    #[error("participating sync committee public key at index {index} is invalid")]
    InvalidSyncCommitteePublicKey { index: usize },

    #[error("sync committee aggregate signature is invalid")]
    InvalidSyncCommitteeSignature,

    #[error("arithmetic error during light-client validation: {0:?}")]
    Arithmetic(ArithError),
}

impl From<ArithError> for LightClientSyncError {
    fn from(error: ArithError) -> Self {
        Self::Arithmetic(error)
    }
}
