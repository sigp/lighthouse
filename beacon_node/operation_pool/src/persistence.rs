use crate::attestation_id::AttestationId;
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
    variants(Base, Altair),
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
    /// Mapping from attestation ID to attestation mappings.
    // We could save space by not storing the attestation ID, but it might
    // be difficult to make that roundtrip due to eager aggregation.
    attestations: Vec<(AttestationId, Vec<Attestation<T>>)>,
    /// Mapping from sync contribution ID to sync contributions and aggregate.
    #[superstruct(only(Altair))]
    sync_contributions: PersistedSyncContributions<T>,
    /// Attester slashings.
    attester_slashings: Vec<(AttesterSlashing<T>, ForkVersion)>,
    /// Proposer slashings.
    proposer_slashings: Vec<ProposerSlashing>,
    /// Voluntary exits.
    voluntary_exits: Vec<SignedVoluntaryExit>,
}

impl<T: EthSpec> PersistedOperationPool<T> {
    /// Convert an `OperationPool` into serializable form. Always converts to
    /// `PersistedOperationPool::Altair` because the v3 to v4 database schema migration ensures
    /// the op pool is always persisted as the Altair variant.
    pub fn from_operation_pool(operation_pool: &OperationPool<T>) -> Self {
        let attestations = operation_pool
            .attestations
            .read()
            .iter()
            .map(|(att_id, att)| (att_id.clone(), att.clone()))
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

        PersistedOperationPool::Altair(PersistedOperationPoolAltair {
            attestations,
            sync_contributions,
            attester_slashings,
            proposer_slashings,
            voluntary_exits,
        })
    }

    /// Reconstruct an `OperationPool`. Sets `sync_contributions` to its `Default` if `self` matches
    /// `PersistedOperationPool::Base`.
    pub fn into_operation_pool(self) -> Result<OperationPool<T>, OpPoolError> {
        let attestations = RwLock::new(self.attestations().to_vec().into_iter().collect());
        let attester_slashings =
            RwLock::new(self.attester_slashings().to_vec().into_iter().collect());
        let proposer_slashings = RwLock::new(
            self.proposer_slashings()
                .to_vec()
                .into_iter()
                .map(|slashing| (slashing.signed_header_1.message.proposer_index, slashing))
                .collect(),
        );
        let voluntary_exits = RwLock::new(
            self.voluntary_exits()
                .to_vec()
                .into_iter()
                .map(|exit| (exit.message.validator_index, exit))
                .collect(),
        );
        let op_pool = match self {
            PersistedOperationPool::Base(_) => OperationPool {
                attestations,
                sync_contributions: <_>::default(),
                attester_slashings,
                proposer_slashings,
                voluntary_exits,
                _phantom: Default::default(),
            },
            PersistedOperationPool::Altair(_) => {
                let sync_contributions =
                    RwLock::new(self.sync_contributions()?.to_vec().into_iter().collect());

                OperationPool {
                    attestations,
                    sync_contributions,
                    attester_slashings,
                    proposer_slashings,
                    voluntary_exits,
                    _phantom: Default::default(),
                }
            }
        };
        Ok(op_pool)
    }

    /// Convert the `PersistedOperationPool::Base` variant to `PersistedOperationPool::Altair` by
    /// setting `sync_contributions` to its default.
    pub fn base_to_altair(self) -> Self {
        match self {
            PersistedOperationPool::Base(_) => {
                PersistedOperationPool::Altair(PersistedOperationPoolAltair {
                    attestations: self.attestations().to_vec(),
                    sync_contributions: <_>::default(),
                    attester_slashings: self.attester_slashings().to_vec(),
                    proposer_slashings: self.proposer_slashings().to_vec(),
                    voluntary_exits: self.voluntary_exits().to_vec(),
                })
            }
            PersistedOperationPool::Altair(_) => self,
        }
    }
}

/// This `StoreItem` implementation is necessary for migrating the `PersistedOperationPool`
/// in the v3 to v4 database schema migration.
impl<T: EthSpec> StoreItem for PersistedOperationPoolBase<T> {
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

/// Deserialization for `PersistedOperationPool` defaults to `PersistedOperationPool::Altair`
/// because the v3 to v4 database schema migration ensures the persisted op pool is always stored
/// in the Altair format.
impl<T: EthSpec> StoreItem for PersistedOperationPool<T> {
    fn db_column() -> DBColumn {
        DBColumn::OpPool
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        // Default deserialization to the Altair variant.
        PersistedOperationPoolAltair::from_ssz_bytes(bytes)
            .map(Self::Altair)
            .map_err(Into::into)
    }
}
