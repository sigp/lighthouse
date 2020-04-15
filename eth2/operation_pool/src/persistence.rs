use crate::attestation_id::AttestationId;
use crate::OperationPool;
use parking_lot::RwLock;
use serde_derive::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use store::{DBColumn, Error as StoreError, SimpleStoreItem};
use types::*;

/// SSZ-serializable version of `OperationPool`.
///
/// Operations are stored in arbitrary order, so it's not a good idea to compare instances
/// of this type (or its encoded form) for equality. Convert back to an `OperationPool` first.
#[derive(Clone, PartialEq, Debug, Encode, Decode, Serialize, Deserialize)]
#[serde(bound = "T: EthSpec")]
pub struct PersistedOperationPool<T: EthSpec> {
    /// Mapping from attestation ID to attestation mappings.
    // We could save space by not storing the attestation ID, but it might
    // be difficult to make that roundtrip due to eager aggregation.
    attestations: Vec<(AttestationId, Vec<Attestation<T>>)>,
    /// Attester slashings.
    attester_slashings: Vec<AttesterSlashing<T>>,
    /// Proposer slashings.
    proposer_slashings: Vec<ProposerSlashing>,
    /// Voluntary exits.
    voluntary_exits: Vec<SignedVoluntaryExit>,
}

impl<T: EthSpec> PersistedOperationPool<T> {
    /// Convert an `OperationPool` into serializable form.
    pub fn from_operation_pool(operation_pool: &OperationPool<T>) -> Self {
        let attestations = operation_pool
            .attestations
            .read()
            .iter()
            .map(|(att_id, att)| (att_id.clone(), att.clone()))
            .collect();

        let attester_slashings = operation_pool
            .attester_slashings
            .read()
            .iter()
            .map(|(_, slashing)| slashing.clone())
            .collect();

        let proposer_slashings = operation_pool
            .proposer_slashings
            .read()
            .iter()
            .map(|(_, slashing)| slashing.clone())
            .collect();

        let voluntary_exits = operation_pool
            .voluntary_exits
            .read()
            .iter()
            .map(|(_, exit)| exit.clone())
            .collect();

        Self {
            attestations,
            attester_slashings,
            proposer_slashings,
            voluntary_exits,
        }
    }

    /// Reconstruct an `OperationPool`.
    pub fn into_operation_pool(self, state: &BeaconState<T>, spec: &ChainSpec) -> OperationPool<T> {
        let attestations = RwLock::new(self.attestations.into_iter().collect());
        let attester_slashings = RwLock::new(
            self.attester_slashings
                .into_iter()
                .map(|slashing| {
                    (
                        OperationPool::attester_slashing_id(&slashing, state, spec),
                        slashing,
                    )
                })
                .collect(),
        );
        let proposer_slashings = RwLock::new(
            self.proposer_slashings
                .into_iter()
                .map(|slashing| (slashing.signed_header_1.message.proposer_index, slashing))
                .collect(),
        );
        let voluntary_exits = RwLock::new(
            self.voluntary_exits
                .into_iter()
                .map(|exit| (exit.message.validator_index, exit))
                .collect(),
        );

        OperationPool {
            attestations,
            attester_slashings,
            proposer_slashings,
            voluntary_exits,
            _phantom: Default::default(),
        }
    }
}

impl<T: EthSpec> SimpleStoreItem for PersistedOperationPool<T> {
    fn db_column() -> DBColumn {
        DBColumn::OpPool
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        Self::from_ssz_bytes(bytes).map_err(Into::into)
    }
}
