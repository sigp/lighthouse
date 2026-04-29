//! Abstraction layer for data availability operations across different DA checkers.
//!
//! This module provides a unified interface for availability operations that are shared
//! between the legacy `DataAvailabilityChecker` (for blocks) and
//! `DataAvailabilityCache` (for payload envelopes after Gloas).
//!
//! ## Design
//!
//! - **Unified operations**: Shared column operations dispatched to v1 or v2
//! - **Fork-aware routing**: `DataAvailabilityRouter` dispatches to v1 or v2 based on slot
//! - **Processing**: `BeaconChain::process_availability_outcome()` handles both result types
//!
//! After Gloas is fully activated and v1 is deprecated, this can be deleted and we can
//! use the Gloas DA checker directly.

use crate::BeaconChainTypes;
use crate::BlockProcessStatus;
use crate::blob_verification::{GossipVerifiedBlob, KzgVerifiedBlob};
use crate::block_verification_types::AvailabilityPendingExecutedBlock;
use crate::custody_context::CustodyContext;
use crate::data_availability_checker::{
    Availability as BlockAvailability, AvailabilityCheckError, AvailableBlock,
    DataAvailabilityChecker, DataAvailabilityCheckerMetrics as BlockMetrics,
    DataColumnReconstructionResult as BlockReconstructionResult, MissingCellsError,
};
use crate::data_column_verification::{GossipVerifiedDataColumn, KzgVerifiedCustodyDataColumn};
use crate::observed_data_sidecars::ObservationStrategy;
use crate::pending_payload_cache::{
    Availability as PayloadAvailability, DataAvailabilityCheckerMetrics as PayloadMetrics,
    DataColumnReconstructionResult as PayloadReconstructionResult, PendingPayloadCache,
};
use std::sync::Arc;
use types::data::{BlobIdentifier, FixedBlobSidecarList};
use types::{
    BlobSidecar, BlockImportSource, ChainSpec, ColumnIndex, DataColumnSidecar,
    DataColumnSidecarList, Epoch, EthSpec, ForkName, Hash256, PartialDataColumnSidecarRef,
    SignedBeaconBlock, Slot,
};

/// Unified result from operations that can come from either DA checker.
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
            Self::Payload(PayloadAvailability::Available(available_data)) => {
                available_data.envelope.message().beacon_block_root
            }
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

/// Router that directs data availability checker operations to the appropriate version based on fork.
///
/// This wraps both the legacy (v1) and Gloas (v2) DA checkers, providing unified operations
/// that dispatch to the correct checker based on fork.
///
/// After Gloas is fully activated and v1 is deprecated, this router can be deleted and
/// we can use the V2 DA checker directly.
pub struct DataAvailabilityRouter<T: BeaconChainTypes> {
    /// Legacy DA checker for pre-Gloas blocks
    pending_block_cache: Arc<DataAvailabilityChecker<T>>,
    /// Gloas DA checker for payload envelopes
    pending_payload_cache: Arc<PendingPayloadCache<T>>,
    spec: Arc<ChainSpec>,
}

impl<T: BeaconChainTypes> DataAvailabilityRouter<T> {
    pub fn new(
        pending_block_cache: Arc<DataAvailabilityChecker<T>>,
        pending_payload_cache: Arc<PendingPayloadCache<T>>,
        spec: Arc<ChainSpec>,
    ) -> Self {
        Self {
            pending_block_cache,
            pending_payload_cache,
            spec,
        }
    }

    /// Returns true if the given slot is in the Gloas fork or later.
    fn is_gloas(&self, slot: Slot) -> bool {
        self.spec
            .fork_name_at_slot::<T::EthSpec>(slot)
            .gloas_enabled()
    }

    // ── Shared methods (dispatched to v1 or v2 based on fork) ──

    /// Returns the custody context (same for both checkers).
    pub fn custody_context(&self) -> &Arc<CustodyContext<T::EthSpec>> {
        // Both checkers share the same custody context
        self.pending_block_cache.custody_context()
    }

    /// Query data columns from the appropriate checker based on fork.
    pub fn get_data_columns(
        &self,
        block_root: Hash256,
        fork_name: ForkName,
    ) -> Option<DataColumnSidecarList<T::EthSpec>> {
        if fork_name.gloas_enabled() {
            self.pending_payload_cache.get_data_columns(block_root)
        } else {
            self.pending_block_cache.get_data_columns(block_root)
        }
    }

    pub fn missing_cells_for_column_sidecar<'a>(
        &'_ self,
        slot: Slot,
        data_column: &'a DataColumnSidecar<T::EthSpec>,
    ) -> Result<Option<PartialDataColumnSidecarRef<'a, T::EthSpec>>, MissingCellsError> {
        if self.is_gloas(slot) {
            self.pending_payload_cache
                .missing_cells_for_column_sidecar(data_column)
        } else {
            self.pending_block_cache
                .missing_cells_for_column_sidecar(data_column)
        }
    }

    /// Get cached column indexes from the appropriate checker based on slot.
    pub fn cached_data_column_indexes(
        &self,
        block_root: &Hash256,
        slot: Slot,
    ) -> Option<Vec<ColumnIndex>> {
        if self.is_gloas(slot) {
            self.pending_payload_cache
                .cached_data_column_indexes(block_root)
        } else {
            self.pending_block_cache
                .cached_data_column_indexes(block_root)
        }
    }

    /// Insert RPC custody columns, routing to the correct checker based on slot.
    pub fn put_rpc_custody_columns(
        &self,
        block_root: Hash256,
        slot: Slot,
        custody_columns: DataColumnSidecarList<T::EthSpec>,
    ) -> Result<AvailabilityOutcome<T::EthSpec>, AvailabilityCheckError> {
        if self.is_gloas(slot) {
            self.pending_payload_cache
                .put_rpc_custody_columns(block_root, slot, custody_columns)
                .map(AvailabilityOutcome::Payload)
        } else {
            self.pending_block_cache
                .put_rpc_custody_columns(block_root, slot, custody_columns)
                .map(AvailabilityOutcome::Block)
        }
    }

    /// Insert gossip-verified data columns, routing to the correct checker based on slot.
    pub fn put_gossip_verified_data_columns<O: ObservationStrategy>(
        &self,
        block_root: Hash256,
        slot: Slot,
        data_columns: Vec<GossipVerifiedDataColumn<T, O>>,
    ) -> Result<AvailabilityOutcome<T::EthSpec>, AvailabilityCheckError> {
        if self.is_gloas(slot) {
            self.pending_payload_cache
                .put_gossip_verified_data_columns(block_root, slot, data_columns)
                .map(AvailabilityOutcome::Payload)
        } else {
            self.pending_block_cache
                .put_gossip_verified_data_columns(block_root, slot, data_columns)
                .map(AvailabilityOutcome::Block)
        }
    }

    /// Insert KZG-verified custody data columns, routing to the correct checker based on slot.
    pub fn put_kzg_verified_custody_data_columns(
        &self,
        block_root: Hash256,
        slot: Slot,
        custody_columns: Vec<KzgVerifiedCustodyDataColumn<T::EthSpec>>,
    ) -> Result<AvailabilityOutcome<T::EthSpec>, AvailabilityCheckError> {
        if self.is_gloas(slot) {
            self.pending_payload_cache
                .put_kzg_verified_custody_data_columns(block_root, custody_columns)
                .map(AvailabilityOutcome::Payload)
        } else {
            self.pending_block_cache
                .put_kzg_verified_custody_data_columns(block_root, custody_columns)
                .map(AvailabilityOutcome::Block)
        }
    }

    /// Attempt to reconstruct missing data columns, routing to the correct checker based on slot.
    pub fn reconstruct_data_columns(
        &self,
        block_root: &Hash256,
        slot: Slot,
    ) -> Result<ReconstructionOutcome<T::EthSpec>, AvailabilityCheckError> {
        if self.is_gloas(slot) {
            self.pending_payload_cache
                .reconstruct_data_columns(block_root)
                .map(ReconstructionOutcome::Payload)
        } else {
            self.pending_block_cache
                .reconstruct_data_columns(block_root)
                .map(ReconstructionOutcome::Block)
        }
    }

    // ── V1-only methods (blobs, blocks, boundary queries) ──

    /// Returns the data availability boundary epoch (v1).
    pub fn data_availability_boundary(&self) -> Option<Epoch> {
        self.pending_block_cache.data_availability_boundary()
    }

    /// Returns whether a DA check is required for the given epoch (v1).
    pub fn da_check_required_for_epoch(&self, epoch: Epoch) -> bool {
        self.pending_block_cache.da_check_required_for_epoch(epoch)
    }

    /// Returns whether blobs are required for the given epoch (v1).
    pub fn blobs_required_for_epoch(&self, epoch: Epoch) -> bool {
        self.pending_block_cache.blobs_required_for_epoch(epoch)
    }

    /// Returns whether data columns are required for the given epoch (v1).
    pub fn data_columns_required_for_epoch(&self, epoch: Epoch) -> bool {
        self.pending_block_cache
            .data_columns_required_for_epoch(epoch)
    }

    /// Verifies KZG commitments for a single available block (v1).
    pub fn verify_kzg_for_available_block(
        &self,
        available_block: &AvailableBlock<T::EthSpec>,
    ) -> Result<(), AvailabilityCheckError> {
        self.pending_block_cache
            .verify_kzg_for_available_block(available_block)
    }

    /// Batch verifies KZG commitments for multiple available blocks (v1).
    pub fn batch_verify_kzg_for_available_blocks(
        &self,
        available_blocks: &[AvailableBlock<T::EthSpec>],
    ) -> Result<(), AvailabilityCheckError> {
        self.pending_block_cache
            .batch_verify_kzg_for_available_blocks(available_blocks)
    }

    /// Get a blob from the availability cache (v1).
    pub fn get_blob(
        &self,
        blob_id: &BlobIdentifier,
    ) -> Result<Option<Arc<BlobSidecar<T::EthSpec>>>, AvailabilityCheckError> {
        self.pending_block_cache.get_blob(blob_id)
    }

    /// Returns the cached blob indexes for a given block root (v1).
    pub fn cached_blob_indexes(&self, block_root: &Hash256) -> Option<Vec<u64>> {
        self.pending_block_cache.cached_blob_indexes(block_root)
    }

    /// Returns the cached block for a given block root (v1).
    pub fn get_cached_block(&self, block_root: &Hash256) -> Option<BlockProcessStatus<T::EthSpec>> {
        self.pending_block_cache.get_cached_block(block_root)
    }

    /// Inserts a pre-execution block into the cache.
    pub fn put_pre_execution_block(
        &self,
        block_root: Hash256,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
        source: BlockImportSource,
    ) -> Result<(), AvailabilityCheckError> {
        if let ForkName::Gloas = block.fork_name_unchecked() {
            self.pending_payload_cache
                .init_pending_block(block_root, block);
            Ok(())
        } else {
            self.pending_block_cache
                .put_pre_execution_block(block_root, block, source)
        }
    }

    /// Insert an executed block and check availability (v1).
    pub fn put_executed_block(
        &self,
        executed_block: AvailabilityPendingExecutedBlock<T::EthSpec>,
    ) -> Result<BlockAvailability<T::EthSpec>, AvailabilityCheckError> {
        self.pending_block_cache.put_executed_block(executed_block)
    }

    /// Removes a pre-execution block from the cache on execution error (v1).
    pub fn remove_block_on_execution_error(&self, block_root: &Hash256) {
        self.pending_block_cache
            .remove_block_on_execution_error(block_root)
    }

    /// Insert blobs received via RPC and check availability (v1).
    pub fn put_rpc_blobs(
        &self,
        block_root: Hash256,
        blobs: FixedBlobSidecarList<T::EthSpec>,
    ) -> Result<BlockAvailability<T::EthSpec>, AvailabilityCheckError> {
        self.pending_block_cache.put_rpc_blobs(block_root, blobs)
    }

    /// Insert KZG-verified blobs and check availability (v1).
    pub fn put_kzg_verified_blobs<I: IntoIterator<Item = KzgVerifiedBlob<T::EthSpec>>>(
        &self,
        block_root: Hash256,
        blobs: I,
    ) -> Result<BlockAvailability<T::EthSpec>, AvailabilityCheckError> {
        self.pending_block_cache
            .put_kzg_verified_blobs(block_root, blobs)
    }

    /// Insert gossip-verified blobs into the v1 checker.
    pub fn put_gossip_verified_blobs<
        I: IntoIterator<Item = GossipVerifiedBlob<T, O>>,
        O: ObservationStrategy,
    >(
        &self,
        block_root: Hash256,
        blobs: I,
    ) -> Result<BlockAvailability<T::EthSpec>, AvailabilityCheckError> {
        self.pending_block_cache
            .put_gossip_verified_blobs(block_root, blobs)
    }

    // ── Metrics ──

    pub fn metrics(&self) -> DataAvailabilityRouterMetrics {
        DataAvailabilityRouterMetrics {
            block: self.pending_block_cache.metrics(),
            payload: self.pending_payload_cache.metrics(),
        }
    }

    // ── Direct access ──

    /// Direct access to the block-level DA checker (pre-Gloas).
    /// Used for block availability checks, range sync, and blob verification.
    pub fn pending_block_cache(&self) -> &Arc<DataAvailabilityChecker<T>> {
        &self.pending_block_cache
    }

    /// Direct access to the envelope-level DA checker (Gloas).
    /// Used for payload envelope availability checks and column verification.
    pub fn pending_payload_cache(&self) -> &Arc<PendingPayloadCache<T>> {
        &self.pending_payload_cache
    }
}

pub struct DataAvailabilityRouterMetrics {
    pub block: BlockMetrics,
    pub payload: PayloadMetrics,
}

pub fn start_availability_cache_maintenance_service<T: BeaconChainTypes>(
    executor: task_executor::TaskExecutor,
    chain: Arc<crate::BeaconChain<T>>,
) {
    crate::data_availability_checker::start_availability_cache_maintenance_service(
        executor.clone(),
        chain.clone(),
    );
    crate::pending_payload_cache::start_availability_cache_maintenance_service(executor, chain);
}
