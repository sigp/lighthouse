//! Abstraction layer for data column storage across different DA checkers.
//!
//! This module provides a unified interface for data column operations that are shared
//! between the legacy `DataAvailabilityChecker` (v1, for blocks) and
//! `DataAvailabilityChecker` v2 (for payload envelopes after Gloas).
//!
//! ## Design
//!
//! - **Read operations**: Unified via the `DataColumnCache` trait
//! - **Write operations**: Return `AvailabilityOutcome` enum that wraps both checker types
//! - **Processing**: `BeaconChain::process_availability_outcome()` handles both cases
//!
//! After Gloas is fully activated and v1 is deprecated, this can be deleted and we can
//! use the Gloas DA checker directly.

use crate::BeaconChainTypes;
use crate::custody_context::CustodyContext;
use crate::data_availability_checker::{
    Availability as BlockAvailability, AvailabilityCheckError,
    DataColumnReconstructionResult as BlockReconstructionResult,
};
use crate::data_availability_checker_v2::{
    Availability as PayloadAvailability,
    DataColumnReconstructionResult as PayloadReconstructionResult,
};
use crate::data_column_verification::{GossipVerifiedDataColumn, KzgVerifiedCustodyDataColumn};
use crate::observed_data_sidecars::ObservationStrategy;
use std::sync::Arc;
use types::{
    ChainSpec, ColumnIndex, DataColumnSidecar, DataColumnSidecarList, EthSpec, ForkName, Hash256,
    Slot,
};

/// Unified result from write operations that can come from either DA checker.
///
/// This enum allows callers to handle availability from both v1 (blocks) and v2 (payloads)
/// through a single type, with downstream processing handled by `BeaconChain::process_availability_outcome()`.
#[derive(Debug)]
pub enum AvailabilityOutcome<E: EthSpec> {
    /// Block became available (pre-Gloas, from v1 checker)
    Block(BlockAvailability<E>),
    /// Payload became available (post-Gloas, from v2 checker)
    Payload(PayloadAvailability<E>),
}

impl<E: EthSpec> AvailabilityOutcome<E> {
    /// Returns `true` if data is fully available and ready for import.
    pub fn is_available(&self) -> bool {
        match self {
            Self::Block(BlockAvailability::Available(_)) => true,
            Self::Block(BlockAvailability::MissingComponents(_)) => false,
            Self::Payload(PayloadAvailability::Available(_)) => true,
            Self::Payload(PayloadAvailability::MissingComponents(_)) => false,
        }
    }

    /// Returns the block root, regardless of availability status.
    pub fn block_root(&self) -> Hash256 {
        match self {
            Self::Block(BlockAvailability::Available(block)) => block.import_data.block_root,
            Self::Block(BlockAvailability::MissingComponents(root)) => *root,
            // For payload availability, the first element of the tuple is the block root
            Self::Payload(PayloadAvailability::Available(available_data)) => available_data.0,
            Self::Payload(PayloadAvailability::MissingComponents(root)) => *root,
        }
    }

    /// Converts to the inner block availability if this is a block outcome.
    pub fn into_block(self) -> Option<BlockAvailability<E>> {
        match self {
            Self::Block(avail) => Some(avail),
            Self::Payload(_) => None,
        }
    }

    /// Converts to the inner payload availability if this is a payload outcome.
    pub fn into_payload(self) -> Option<PayloadAvailability<E>> {
        match self {
            Self::Block(_) => None,
            Self::Payload(avail) => Some(avail),
        }
    }
}

/// Unified result from reconstruction operations.
#[derive(Debug)]
pub enum ReconstructionOutcome<E: EthSpec> {
    /// Block reconstruction result (pre-Gloas)
    Block(BlockReconstructionResult<E>),
    /// Payload reconstruction result (post-Gloas)
    Payload(PayloadReconstructionResult<E>),
}

impl<E: EthSpec> ReconstructionOutcome<E> {
    /// Returns the reconstructed columns if successful, regardless of type.
    pub fn reconstructed_columns(&self) -> Option<&DataColumnSidecarList<E>> {
        match self {
            Self::Block(BlockReconstructionResult::Success((_, cols))) => Some(cols),
            Self::Payload(PayloadReconstructionResult::Success((_, cols))) => Some(cols),
            _ => None,
        }
    }

    /// Returns true if reconstruction was successful.
    pub fn is_success(&self) -> bool {
        matches!(
            self,
            Self::Block(BlockReconstructionResult::Success(_))
                | Self::Payload(PayloadReconstructionResult::Success(_))
        )
    }

    /// Returns the reason if reconstruction was not started or columns not imported.
    pub fn reason(&self) -> Option<&'static str> {
        match self {
            Self::Block(BlockReconstructionResult::NotStarted(r)) => Some(r),
            Self::Block(BlockReconstructionResult::RecoveredColumnsNotImported(r)) => Some(r),
            Self::Payload(PayloadReconstructionResult::NotStarted(r)) => Some(r),
            Self::Payload(PayloadReconstructionResult::RecoveredColumnsNotImported(r)) => Some(r),
            _ => None,
        }
    }
}

/// Trait for data column operations on availability checkers.
///
/// Both `DataAvailabilityChecker` (v1) and `DataAvailabilityChecker` (v2) implement
/// this trait. The associated types differ:
/// - V1: Returns `Availability<E>` containing `AvailableExecutedBlock<E>`
/// - V2: Returns `Availability<E>` containing `(Hash256, DataColumnSidecarList<E>)` (block root + columns)
pub trait DataColumnCache<T: BeaconChainTypes>: Send + Sync {
    /// The availability type returned by write operations.
    /// V1 returns block availability, V2 returns payload availability.
    type Availability;

    /// The reconstruction result type.
    /// V1 returns `DataColumnReconstructionResult` with block availability.
    /// V2 returns `DataColumnReconstructionResult` with payload availability.
    type ReconstructionResult;

    /// Returns the custody context used by this checker.
    fn custody_context(&self) -> &Arc<CustodyContext<T::EthSpec>>;

    /// Returns all cached data columns for the given block root, if any.
    fn get_data_columns(&self, block_root: Hash256) -> Option<DataColumnSidecarList<T::EthSpec>>;

    /// Returns the indices of cached data columns for the given block root.
    fn cached_data_column_indexes(&self, block_root: &Hash256) -> Option<Vec<ColumnIndex>>;

    /// Checks if a specific data column is cached for the given block root.
    fn is_data_column_cached(
        &self,
        block_root: &Hash256,
        data_column: &DataColumnSidecar<T::EthSpec>,
    ) -> bool;

    /// Insert RPC custody columns and check if the block/payload becomes available.
    fn put_rpc_custody_columns(
        &self,
        block_root: Hash256,
        slot: Slot,
        custody_columns: DataColumnSidecarList<T::EthSpec>,
    ) -> Result<Self::Availability, AvailabilityCheckError>;

    /// Insert gossip-verified data columns and check availability.
    fn put_gossip_verified_data_columns<O: ObservationStrategy>(
        &self,
        block_root: Hash256,
        slot: Slot,
        data_columns: Vec<GossipVerifiedDataColumn<T, O>>,
    ) -> Result<Self::Availability, AvailabilityCheckError>;

    /// Insert KZG-verified custody data columns and check availability.
    fn put_kzg_verified_custody_data_columns(
        &self,
        block_root: Hash256,
        custody_columns: Vec<KzgVerifiedCustodyDataColumn<T::EthSpec>>,
    ) -> Result<Self::Availability, AvailabilityCheckError>;

    /// Attempt to reconstruct missing data columns from available ones.
    fn reconstruct_data_columns(
        &self,
        block_root: &Hash256,
    ) -> Result<Self::ReconstructionResult, AvailabilityCheckError>;
}

/// Router that directs data availability checker operations to the appropriate version based on fork.
///
/// This wraps both the legacy (v1) and Gloas (v2) DA checkers, providing:
/// - Unified read operations that query both checkers
/// - Fork-aware routing for write operations that return `AvailabilityOutcome`
///
/// After Gloas is fully activated and v1 is deprecated, this router can be deleted and
/// we can use the Gloas DA checker directly.
pub struct DataAvailabilityRouter<T: BeaconChainTypes, V1, V2>
where
    V1: DataColumnCache<
            T,
            Availability = BlockAvailability<T::EthSpec>,
            ReconstructionResult = BlockReconstructionResult<T::EthSpec>,
        >,
    V2: DataColumnCache<
            T,
            Availability = PayloadAvailability<T::EthSpec>,
            ReconstructionResult = PayloadReconstructionResult<T::EthSpec>,
        >,
{
    /// Legacy DA checker for pre-Gloas blocks
    v1: Arc<V1>,
    /// Gloas DA checker for payload envelopes
    v2: Arc<V2>,
    spec: Arc<ChainSpec>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: BeaconChainTypes, V1, V2> DataAvailabilityRouter<T, V1, V2>
where
    V1: DataColumnCache<
            T,
            Availability = BlockAvailability<T::EthSpec>,
            ReconstructionResult = BlockReconstructionResult<T::EthSpec>,
        >,
    V2: DataColumnCache<
            T,
            Availability = PayloadAvailability<T::EthSpec>,
            ReconstructionResult = PayloadReconstructionResult<T::EthSpec>,
        >,
{
    pub fn new(v1: Arc<V1>, v2: Arc<V2>, spec: Arc<ChainSpec>) -> Self {
        Self {
            v1,
            v2,
            spec,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Returns true if the given slot is in the Gloas fork or later.
    fn is_gloas(&self, slot: Slot) -> bool {
        self.spec
            .fork_name_at_slot::<T::EthSpec>(slot)
            .gloas_enabled()
    }

    /// Returns the custody context (same for both checkers).
    pub fn custody_context(&self) -> &Arc<CustodyContext<T::EthSpec>> {
        // Both checkers share the same custody context
        self.v1.custody_context()
    }

    /// Query data columns from the appropriate checker based on slot.
    pub fn get_data_columns(
        &self,
        block_root: Hash256,
        fork_name: ForkName,
    ) -> Option<DataColumnSidecarList<T::EthSpec>> {
        if fork_name.gloas_enabled() {
            self.v2.get_data_columns(block_root)
        } else {
            self.v1.get_data_columns(block_root)
        }
    }

    /// Query data columns from both checkers, returning the first match.
    ///
    /// Use this when you don't know which fork the block belongs to, or during
    /// the transition period when data might be in either checker.
    pub fn get_data_columns_any(
        &self,
        block_root: Hash256,
    ) -> Option<DataColumnSidecarList<T::EthSpec>> {
        self.v1
            .get_data_columns(block_root)
            .or_else(|| self.v2.get_data_columns(block_root))
    }

    pub fn is_data_column_cached(
        &self,
        slot: Slot,
        block_root: &Hash256,
        data_column: &DataColumnSidecar<T::EthSpec>,
    ) -> bool {
        if self.is_gloas(slot) {
            self.v2.is_data_column_cached(block_root, data_column)
        } else {
            self.v1.is_data_column_cached(block_root, data_column)
        }
    }

    /// Get cached column indexes from the appropriate checker based on slot.
    pub fn cached_data_column_indexes(
        &self,
        block_root: &Hash256,
        slot: Slot,
    ) -> Option<Vec<ColumnIndex>> {
        if self.is_gloas(slot) {
            self.v2.cached_data_column_indexes(block_root)
        } else {
            self.v1.cached_data_column_indexes(block_root)
        }
    }

    /// Insert RPC custody columns, routing to the correct checker based on fork.
    pub fn put_rpc_custody_columns(
        &self,
        block_root: Hash256,
        slot: Slot,
        custody_columns: DataColumnSidecarList<T::EthSpec>,
    ) -> Result<AvailabilityOutcome<T::EthSpec>, AvailabilityCheckError> {
        if self.is_gloas(slot) {
            self.v2
                .put_rpc_custody_columns(block_root, slot, custody_columns)
                .map(AvailabilityOutcome::Payload)
        } else {
            self.v1
                .put_rpc_custody_columns(block_root, slot, custody_columns)
                .map(AvailabilityOutcome::Block)
        }
    }

    /// Insert gossip-verified data columns, routing to the correct checker based on fork.
    pub fn put_gossip_verified_data_columns<O: ObservationStrategy>(
        &self,
        block_root: Hash256,
        slot: Slot,
        data_columns: Vec<GossipVerifiedDataColumn<T, O>>,
    ) -> Result<AvailabilityOutcome<T::EthSpec>, AvailabilityCheckError> {
        if self.is_gloas(slot) {
            self.v2
                .put_gossip_verified_data_columns(block_root, slot, data_columns)
                .map(AvailabilityOutcome::Payload)
        } else {
            self.v1
                .put_gossip_verified_data_columns(block_root, slot, data_columns)
                .map(AvailabilityOutcome::Block)
        }
    }

    /// Insert KZG-verified custody data columns, routing to the correct checker based on fork.
    pub fn put_kzg_verified_custody_data_columns(
        &self,
        block_root: Hash256,
        slot: Slot,
        custody_columns: Vec<KzgVerifiedCustodyDataColumn<T::EthSpec>>,
    ) -> Result<AvailabilityOutcome<T::EthSpec>, AvailabilityCheckError> {
        if self.is_gloas(slot) {
            self.v2
                .put_kzg_verified_custody_data_columns(block_root, custody_columns)
                .map(AvailabilityOutcome::Payload)
        } else {
            self.v1
                .put_kzg_verified_custody_data_columns(block_root, custody_columns)
                .map(AvailabilityOutcome::Block)
        }
    }

    /// Attempt to reconstruct missing data columns, routing to the correct checker based on fork.
    pub fn reconstruct_data_columns(
        &self,
        block_root: &Hash256,
        slot: Slot,
    ) -> Result<ReconstructionOutcome<T::EthSpec>, AvailabilityCheckError> {
        if self.is_gloas(slot) {
            self.v2
                .reconstruct_data_columns(block_root)
                .map(ReconstructionOutcome::Payload)
        } else {
            self.v1
                .reconstruct_data_columns(block_root)
                .map(ReconstructionOutcome::Block)
        }
    }

    /// Direct access to v1 checker (for block-specific operations).
    ///
    /// Use this for operations that are specific to the legacy block-based DA checker,
    /// such as `put_executed_block`, `get_cached_block`, blob operations, etc.
    pub fn v1(&self) -> Arc<V1> {
        self.v1.clone()
    }

    /// Direct access to v2 checker (for payload-specific operations).
    ///
    /// Use this for operations that are specific to the Gloas payload-based DA checker,
    /// such as `put_executed_payload`, `get_cached_payload`, etc.
    pub fn v2(&self) -> Arc<V2> {
        self.v2.clone()
    }
}
