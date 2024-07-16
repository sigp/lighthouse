use crate::attestation_storage::AttestationMap;
use crate::bls_to_execution_changes::{BlsToExecutionChanges, ReceivedPreCapella};
use crate::sync_aggregate_id::SyncAggregateId;
use crate::OpPoolError;
use crate::OperationPool;
use derivative::Derivative;
use parking_lot::RwLock;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use state_processing::SigVerifiedOp;
use std::collections::HashSet;
use std::mem;
use store::{DBColumn, Error as StoreError, StoreItem};
use types::attestation::AttestationOnDisk;
use types::*;

type PersistedSyncContributions<E> = Vec<(SyncAggregateId, Vec<SyncCommitteeContribution<E>>)>;

/// SSZ-serializable version of `OperationPool`.
///
/// Operations are stored in arbitrary order, so it's not a good idea to compare instances
/// of this type (or its encoded form) for equality. Convert back to an `OperationPool` first.
#[superstruct(
    variants(V15, V20),
    variant_attributes(
        derive(Derivative, PartialEq, Debug, Encode, Decode),
        derivative(Clone),
    ),
    partial_getter_error(ty = "OpPoolError", expr = "OpPoolError::IncorrectOpPoolVariant")
)]
#[derive(PartialEq, Debug, Encode)]
#[ssz(enum_behaviour = "transparent")]
pub struct PersistedOperationPool<E: EthSpec> {
    #[superstruct(only(V15))]
    pub attestations_v15: Vec<(AttestationBase<E>, Vec<u64>)>,
    /// Attestations and their attesting indices.
    #[superstruct(only(V20))]
    pub attestations: Vec<(AttestationOnDisk<E>, Vec<u64>)>,
    /// Mapping from sync contribution ID to sync contributions and aggregate.
    pub sync_contributions: PersistedSyncContributions<E>,
    #[superstruct(only(V15))]
    pub attester_slashings_v15: Vec<SigVerifiedOp<AttesterSlashingBase<E>, E>>,
    /// Attester slashings.
    #[superstruct(only(V20))]
    pub attester_slashings: Vec<SigVerifiedOp<AttesterSlashing<E>, E>>,
    /// Proposer slashings with fork information.
    pub proposer_slashings: Vec<SigVerifiedOp<ProposerSlashing, E>>,
    /// Voluntary exits with fork information.
    pub voluntary_exits: Vec<SigVerifiedOp<SignedVoluntaryExit, E>>,
    /// BLS to Execution Changes
    pub bls_to_execution_changes: Vec<SigVerifiedOp<SignedBlsToExecutionChange, E>>,
    /// Validator indices with BLS to Execution Changes to be broadcast at the
    /// Capella fork.
    pub capella_bls_change_broadcast_indices: Vec<u64>,
}

impl<E: EthSpec> PersistedOperationPool<E> {
    /// Convert an `OperationPool` into serializable form.
    pub fn from_operation_pool(operation_pool: &OperationPool<E>) -> Self {
        let attestations = operation_pool
            .attestations
            .read()
            .iter()
            .map(|att| {
                (
                    AttestationOnDisk::from(att.clone_as_attestation()),
                    att.indexed.attesting_indices().clone(),
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

        let bls_to_execution_changes = operation_pool
            .bls_to_execution_changes
            .read()
            .iter_fifo()
            .map(|bls_to_execution_change| (**bls_to_execution_change).clone())
            .collect();

        let capella_bls_change_broadcast_indices = operation_pool
            .bls_to_execution_changes
            .read()
            .iter_pre_capella_indices()
            .copied()
            .collect();

        PersistedOperationPool::V20(PersistedOperationPoolV20 {
            attestations,
            sync_contributions,
            attester_slashings,
            proposer_slashings,
            voluntary_exits,
            bls_to_execution_changes,
            capella_bls_change_broadcast_indices,
        })
    }

    /// Reconstruct an `OperationPool`.
    pub fn into_operation_pool(mut self) -> Result<OperationPool<E>, OpPoolError> {
        let attester_slashings = match &self {
            PersistedOperationPool::V15(pool_v15) => RwLock::new(
                pool_v15
                    .attester_slashings_v15
                    .iter()
                    .map(|slashing| slashing.clone().into())
                    .collect(),
            ),
            PersistedOperationPool::V20(pool_v20) => {
                RwLock::new(pool_v20.attester_slashings.iter().cloned().collect())
            }
        };

        let proposer_slashings = RwLock::new(
            self.proposer_slashings()
                .iter()
                .cloned()
                .map(|slashing| (slashing.as_inner().proposer_index(), slashing))
                .collect(),
        );
        let voluntary_exits = RwLock::new(
            self.voluntary_exits()
                .iter()
                .cloned()
                .map(|exit| (exit.as_inner().message.validator_index, exit))
                .collect(),
        );
        let sync_contributions = RwLock::new(self.sync_contributions().iter().cloned().collect());
        let attestations = match &self {
            PersistedOperationPool::V15(pool_v15) => {
                let mut map = AttestationMap::default();
                for (att, attesting_indices) in
                    pool_v15
                        .attestations_v15
                        .iter()
                        .map(|(att, attesting_indices)| {
                            (Attestation::Base(att.clone()), attesting_indices.clone())
                        })
                {
                    map.insert(att, attesting_indices);
                }
                RwLock::new(map)
            }
            PersistedOperationPool::V20(pool_v20) => {
                let mut map = AttestationMap::default();
                for (att, attesting_indices) in
                    pool_v20
                        .attestations
                        .iter()
                        .map(|(att, attesting_indices)| {
                            (
                                AttestationRef::from(att.to_ref()).clone_as_attestation(),
                                attesting_indices.clone(),
                            )
                        })
                {
                    map.insert(att, attesting_indices);
                }
                RwLock::new(map)
            }
        };

        let mut bls_to_execution_changes = BlsToExecutionChanges::default();
        let persisted_changes = mem::take(self.bls_to_execution_changes_mut());
        let broadcast_indices: HashSet<_> =
            mem::take(self.capella_bls_change_broadcast_indices_mut())
                .into_iter()
                .collect();

        for bls_to_execution_change in persisted_changes {
            let received_pre_capella = if broadcast_indices
                .contains(&bls_to_execution_change.as_inner().message.validator_index)
            {
                ReceivedPreCapella::Yes
            } else {
                ReceivedPreCapella::No
            };
            bls_to_execution_changes.insert(bls_to_execution_change, received_pre_capella);
        }

        let op_pool = OperationPool {
            attestations,
            sync_contributions,
            attester_slashings,
            proposer_slashings,
            voluntary_exits,
            bls_to_execution_changes: RwLock::new(bls_to_execution_changes),
            reward_cache: Default::default(),
            _phantom: Default::default(),
        };
        Ok(op_pool)
    }
}

impl<E: EthSpec> StoreItem for PersistedOperationPoolV15<E> {
    fn db_column() -> DBColumn {
        DBColumn::OpPool
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        PersistedOperationPoolV15::from_ssz_bytes(bytes).map_err(Into::into)
    }
}

impl<E: EthSpec> StoreItem for PersistedOperationPoolV20<E> {
    fn db_column() -> DBColumn {
        DBColumn::OpPool
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        PersistedOperationPoolV20::from_ssz_bytes(bytes).map_err(Into::into)
    }
}

/// Deserialization for `PersistedOperationPool` defaults to `PersistedOperationPool::V12`.
impl<E: EthSpec> StoreItem for PersistedOperationPool<E> {
    fn db_column() -> DBColumn {
        DBColumn::OpPool
    }

    fn as_store_bytes(&self) -> Vec<u8> {
        self.as_ssz_bytes()
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        // Default deserialization to the latest variant.
        PersistedOperationPoolV20::from_ssz_bytes(bytes)
            .map(Self::V20)
            .map_err(Into::into)
    }
}
