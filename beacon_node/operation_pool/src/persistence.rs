use crate::attestation_id::AttestationId;
use crate::attestation_storage::AttestationMap;
use crate::sync_aggregate_id::SyncAggregateId;
use crate::OpPoolError;
use crate::OperationPool;
use derivative::Derivative;
use parking_lot::RwLock;
use serde_derive::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use store::{DBColumn, Error as StoreError, StoreItem};
use types::*;

type PersistedSyncContributions<T> = Vec<(SyncAggregateId, Vec<SyncCommitteeContribution<T>>)>;

/// SSZ-serializable version of `OperationPool`.
///
/// Operations are stored in arbitrary order, so it's not a good idea to compare instances
/// of this type (or its encoded form) for equality. Convert back to an `OperationPool` first.
#[superstruct(
    variants(V5, V11),
    variant_attributes(
        derive(Derivative, PartialEq, Debug, Serialize, Deserialize, Encode, Decode),
        serde(bound = "T: EthSpec", deny_unknown_fields),
        derivative(Clone),
    ),
    partial_getter_error(ty = "OpPoolError", expr = "OpPoolError::IncorrectOpPoolVariant")
)]
#[derive(PartialEq, Debug, Serialize, Deserialize, Encode)]
#[serde(untagged)]
#[serde(bound = "T: EthSpec")]
#[ssz(enum_behaviour = "transparent")]
pub struct PersistedOperationPool<T: EthSpec> {
    /// [DEPRECATED] Mapping from attestation ID to attestation mappings.
    #[superstruct(only(V5))]
    pub attestations_v5: Vec<(AttestationId, Vec<Attestation<T>>)>,
    /// Attestations and their attesting indices.
    #[superstruct(only(V11))]
    pub attestations: Vec<(Attestation<T>, Vec<u64>)>,
    /// Mapping from sync contribution ID to sync contributions and aggregate.
    pub sync_contributions: PersistedSyncContributions<T>,
    /// Attester slashings.
    pub attester_slashings: Vec<(AttesterSlashing<T>, ForkVersion)>,
    /// Proposer slashings.
    pub proposer_slashings: Vec<ProposerSlashing>,
    /// Voluntary exits.
    pub voluntary_exits: Vec<SignedVoluntaryExit>,
}

impl<T: EthSpec> PersistedOperationPool<T> {
    /// Convert an `OperationPool` into serializable form.
    pub fn from_operation_pool(operation_pool: &OperationPool<T>) -> Self {
        let attestations = operation_pool
            .attestations
            .read()
            .iter()
            .map(|att| {
                (
                    att.clone_as_attestation(),
                    att.indexed.attesting_indices.clone(),
                )
            })
            .collect();

        let sync_contributions = operation_pool
            .sync_contributions
            .read()
            .iter()
            .map(|(id, contribution)| (id.clone(), contribution.clone()))
            .collect();

        let attester_slashings = operation_pool
            .attester_slashings
            .read()
            .iter()
            .cloned()
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

        PersistedOperationPool::V11(PersistedOperationPoolV11 {
            attestations,
            sync_contributions,
            attester_slashings,
            proposer_slashings,
            voluntary_exits,
        })
    }

    /// Reconstruct an `OperationPool`.
    pub fn into_operation_pool(self) -> Result<OperationPool<T>, OpPoolError> {
        let attester_slashings = RwLock::new(self.attester_slashings().iter().cloned().collect());
        let proposer_slashings = RwLock::new(
            self.proposer_slashings()
                .iter()
                .cloned()
                .map(|slashing| (slashing.signed_header_1.message.proposer_index, slashing))
                .collect(),
        );
        let voluntary_exits = RwLock::new(
            self.voluntary_exits()
                .iter()
                .cloned()
                .map(|exit| (exit.message.validator_index, exit))
                .collect(),
        );
        let sync_contributions = RwLock::new(self.sync_contributions().iter().cloned().collect());
        let attestations = match self {
            PersistedOperationPool::V5(_) => return Err(OpPoolError::IncorrectOpPoolVariant),
            PersistedOperationPool::V11(pool) => {
                let mut map = AttestationMap::default();
                for (att, attesting_indices) in pool.attestations {
                    map.insert(att, attesting_indices);
                }
                RwLock::new(map)
            }
        };
        let op_pool = OperationPool {
            attestations,
            sync_contributions,
            attester_slashings,
            proposer_slashings,
            voluntary_exits,
            reward_cache: Default::default(),
            _phantom: Default::default(),
        };
        Ok(op_pool)
    }
}

impl<T: EthSpec> StoreItem for PersistedOperationPoolV5<T> {
    fn db_column() -> DBColumn {
        DBColumn::OpPool
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        PersistedOperationPoolV5::from_ssz_bytes(bytes).map_err(Into::into)
    }
}

/// Deserialization for `PersistedOperationPool` defaults to `PersistedOperationPool::V11`.
impl<T: EthSpec> StoreItem for PersistedOperationPool<T> {
    fn db_column() -> DBColumn {
        DBColumn::OpPool
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        // Default deserialization to the latest variant.
        PersistedOperationPoolV11::from_ssz_bytes(bytes)
            .map(Self::V11)
            .map_err(Into::into)
    }
}
