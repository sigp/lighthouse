use super::AvailableBlockData;
use super::state_lru_cache::{DietAvailabilityPendingExecutedBlock, StateLRUCache};
use crate::CustodyContext;
use crate::beacon_chain::BeaconStore;
use crate::blob_verification::KzgVerifiedBlob;
use crate::block_verification_types::{
    AvailabilityPendingExecutedBlock, AvailableBlock, AvailableExecutedBlock,
};
use crate::data_availability_checker::{Availability, AvailabilityCheckError};
use crate::data_column_verification::KzgVerifiedCustodyDataColumn;
use crate::{BeaconChainTypes, BlockProcessStatus};
use lighthouse_tracing::SPAN_PENDING_COMPONENTS;
use lru::LruCache;
use parking_lot::{MappedRwLockReadGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::cmp::Ordering;
use std::num::NonZeroUsize;
use std::sync::Arc;
use tracing::{Span, debug, debug_span};
use types::beacon_block_body::KzgCommitments;
use types::blob_sidecar::BlobIdentifier;
use types::{
    BlobSidecar, BlockImportSource, ChainSpec, ColumnIndex, DataColumnSidecar,
    DataColumnSidecarList, Epoch, EthSpec, Hash256, RuntimeFixedVector, RuntimeVariableList,
    SignedBeaconBlock,
};

#[derive(Clone)]
pub enum CachedBlock<E: EthSpec> {
    PreExecution(Arc<SignedBeaconBlock<E>>, BlockImportSource),
    Executed(Box<DietAvailabilityPendingExecutedBlock<E>>),
}

impl<E: EthSpec> CachedBlock<E> {
    pub fn get_commitments(&self) -> KzgCommitments<E> {
        let block = self.as_block();
        block
            .message()
            .body()
            .blob_kzg_commitments()
            .cloned()
            .unwrap_or_default()
    }

    fn as_block(&self) -> &SignedBeaconBlock<E> {
        match self {
            CachedBlock::PreExecution(b, _) => b,
            CachedBlock::Executed(b) => b.as_block(),
        }
    }

    pub fn num_blobs_expected(&self) -> usize {
        self.as_block()
            .message()
            .body()
            .blob_kzg_commitments()
            .map_or(0, |commitments| commitments.len())
    }
}

/// This represents the components of a partially available block
///
/// The blobs are all gossip and kzg verified.
/// The block has completed all verifications except the availability check.
///
/// There are currently three distinct hardfork eras that one should take note of:
///     - Pre-Deneb: No availability requirements (Block is immediately available)
///     - Post-Deneb, Pre-PeerDAS: Blobs are needed, but columns are not for the availability check
///     - Post-PeerDAS: Columns are needed, but blobs are not for the availability check
///
/// Note: from this, one can immediately see that `verified_blobs` and `verified_data_columns`
/// are mutually exclusive. i.e. If we are verifying columns to determine a block's availability
/// we are ignoring the `verified_blobs` field.
pub struct PendingComponents<E: EthSpec> {
    pub block_root: Hash256,
    pub verified_blobs: RuntimeFixedVector<Option<KzgVerifiedBlob<E>>>,
    pub verified_data_columns: Vec<KzgVerifiedCustodyDataColumn<E>>,
    pub block: Option<CachedBlock<E>>,
    pub reconstruction_started: bool,
    span: Span,
}

impl<E: EthSpec> PendingComponents<E> {
    /// Returns an immutable reference to the fixed vector of cached blobs.
    pub fn get_cached_blobs(&self) -> &RuntimeFixedVector<Option<KzgVerifiedBlob<E>>> {
        &self.verified_blobs
    }

    #[cfg(test)]
    fn get_diet_block(&self) -> Option<&DietAvailabilityPendingExecutedBlock<E>> {
        self.block.as_ref().and_then(|block| match block {
            CachedBlock::Executed(block) => Some(block.as_ref()),
            _ => None,
        })
    }

    /// Returns an immutable reference to the cached data column.
    pub fn get_cached_data_column(
        &self,
        data_column_index: u64,
    ) -> Option<Arc<DataColumnSidecar<E>>> {
        self.verified_data_columns
            .iter()
            .find(|d| d.index() == data_column_index)
            .map(|d| d.clone_arc())
    }

    /// Returns a mutable reference to the fixed vector of cached blobs.
    pub fn get_cached_blobs_mut(&mut self) -> &mut RuntimeFixedVector<Option<KzgVerifiedBlob<E>>> {
        &mut self.verified_blobs
    }

    /// Checks if a blob exists at the given index in the cache.
    ///
    /// Returns:
    /// - `true` if a blob exists at the given index.
    /// - `false` otherwise.
    pub fn blob_exists(&self, blob_index: usize) -> bool {
        self.get_cached_blobs()
            .get(blob_index)
            .map(|b| b.is_some())
            .unwrap_or(false)
    }

    /// Returns the indices of cached custody columns
    pub fn get_cached_data_columns_indices(&self) -> Vec<ColumnIndex> {
        self.verified_data_columns
            .iter()
            .map(|d| d.index())
            .collect()
    }

    /// Inserts an executed block into the cache.
    pub fn insert_executed_block(&mut self, block: DietAvailabilityPendingExecutedBlock<E>) {
        self.block = Some(CachedBlock::Executed(Box::new(block)))
    }

    /// Inserts a pre-execution block into the cache.
    /// This does NOT override an existing executed block.
    pub fn insert_pre_execution_block(
        &mut self,
        block: Arc<SignedBeaconBlock<E>>,
        source: BlockImportSource,
    ) {
        if self.block.is_none() {
            self.block = Some(CachedBlock::PreExecution(block, source))
        }
    }

    /// Inserts a blob at a specific index in the cache.
    ///
    /// Existing blob at the index will be replaced.
    pub fn insert_blob_at_index(&mut self, blob_index: usize, blob: KzgVerifiedBlob<E>) {
        if let Some(b) = self.get_cached_blobs_mut().get_mut(blob_index) {
            *b = Some(blob);
        }
    }

    /// Merges a given set of blobs into the cache.
    ///
    /// Blobs are only inserted if:
    /// 1. The blob entry at the index is empty and no block exists.
    /// 2. The block exists and its commitment matches the blob's commitment.
    pub fn merge_blobs(&mut self, blobs: RuntimeFixedVector<Option<KzgVerifiedBlob<E>>>) {
        for (index, blob) in blobs.iter().cloned().enumerate() {
            let Some(blob) = blob else { continue };
            self.merge_single_blob(index, blob);
        }
    }

    /// Merges a single blob into the cache.
    ///
    /// Blobs are only inserted if:
    /// 1. The blob entry at the index is empty and no block exists, or
    /// 2. The block exists and its commitment matches the blob's commitment.
    pub fn merge_single_blob(&mut self, index: usize, blob: KzgVerifiedBlob<E>) {
        if let Some(cached_block) = &self.block {
            let block_commitment_opt = cached_block.get_commitments().get(index).copied();
            if let Some(block_commitment) = block_commitment_opt
                && block_commitment == *blob.get_commitment()
            {
                self.insert_blob_at_index(index, blob)
            }
        } else if !self.blob_exists(index) {
            self.insert_blob_at_index(index, blob)
        }
    }

    /// Merges a given set of data columns into the cache.
    fn merge_data_columns<I: IntoIterator<Item = KzgVerifiedCustodyDataColumn<E>>>(
        &mut self,
        kzg_verified_data_columns: I,
    ) -> Result<(), AvailabilityCheckError> {
        for data_column in kzg_verified_data_columns {
            if self.get_cached_data_column(data_column.index()).is_none() {
                self.verified_data_columns.push(data_column);
            }
        }

        Ok(())
    }

    /// Inserts a new block and revalidates the existing blobs against it.
    ///
    /// Blobs that don't match the new block's commitments are evicted.
    pub fn merge_block(&mut self, block: DietAvailabilityPendingExecutedBlock<E>) {
        self.insert_executed_block(block);
        let reinsert = self.get_cached_blobs_mut().take();
        self.merge_blobs(reinsert);
    }

    /// Returns Some if the block has received all its required data for import. The return value
    /// must be persisted in the DB along with the block.
    ///
    /// WARNING: This function can potentially take a lot of time if the state needs to be
    /// reconstructed from disk. Ensure you are not holding any write locks while calling this.
    pub fn make_available<R>(
        &self,
        spec: &Arc<ChainSpec>,
        num_expected_columns_opt: Option<usize>,
        recover: R,
    ) -> Result<Option<AvailableExecutedBlock<E>>, AvailabilityCheckError>
    where
        R: FnOnce(
            DietAvailabilityPendingExecutedBlock<E>,
            &Span,
        ) -> Result<AvailabilityPendingExecutedBlock<E>, AvailabilityCheckError>,
    {
        let Some(CachedBlock::Executed(block)) = &self.block else {
            // Block not available yet
            return Ok(None);
        };

        let num_expected_blobs = block.num_blobs_expected();
        let blob_data = if num_expected_blobs == 0 {
            Some(AvailableBlockData::NoData)
        } else if let Some(num_expected_columns) = num_expected_columns_opt {
            let num_received_columns = self.verified_data_columns.len();
            match num_received_columns.cmp(&num_expected_columns) {
                Ordering::Greater => {
                    // Should never happen
                    return Err(AvailabilityCheckError::Unexpected(format!(
                        "too many columns got {num_received_columns} expected {num_expected_columns}"
                    )));
                }
                Ordering::Equal => {
                    // Block is post-peerdas, and we got enough columns
                    let data_columns = self
                        .verified_data_columns
                        .iter()
                        .map(|d| d.clone().into_inner())
                        .collect::<Vec<_>>();
                    Some(AvailableBlockData::DataColumns(data_columns))
                }
                Ordering::Less => {
                    // Not enough data columns received yet
                    None
                }
            }
        } else {
            // Before PeerDAS, blobs
            let num_received_blobs = self.verified_blobs.iter().flatten().count();
            match num_received_blobs.cmp(&num_expected_blobs) {
                Ordering::Greater => {
                    // Should never happen
                    return Err(AvailabilityCheckError::Unexpected(format!(
                        "too many blobs got {num_received_blobs} expected {num_expected_blobs}"
                    )));
                }
                Ordering::Equal => {
                    let max_blobs = spec.max_blobs_per_block(block.epoch()) as usize;
                    let blobs_vec = self
                        .verified_blobs
                        .iter()
                        .flatten()
                        .map(|blob| blob.clone().to_blob())
                        .collect::<Vec<_>>();
                    let blobs_len = blobs_vec.len();
                    let blobs = RuntimeVariableList::new(blobs_vec, max_blobs).map_err(|_| {
                        AvailabilityCheckError::Unexpected(format!(
                            "over max_blobs len {blobs_len} max {max_blobs}"
                        ))
                    })?;
                    Some(AvailableBlockData::Blobs(blobs))
                }
                Ordering::Less => {
                    // Not enough blobs received yet
                    None
                }
            }
        };

        // Block's data not available yet
        let Some(blob_data) = blob_data else {
            return Ok(None);
        };

        // Block is available, construct `AvailableExecutedBlock`

        let blobs_available_timestamp = match blob_data {
            AvailableBlockData::NoData => None,
            AvailableBlockData::Blobs(_) => self
                .verified_blobs
                .iter()
                .flatten()
                .map(|blob| blob.seen_timestamp())
                .max(),
            // TODO(das): To be fixed with https://github.com/sigp/lighthouse/pull/6850
            AvailableBlockData::DataColumns(_) => None,
        };

        let AvailabilityPendingExecutedBlock {
            block,
            import_data,
            payload_verification_outcome,
        } = recover(*block.clone(), &self.span)?;

        let available_block = AvailableBlock {
            block_root: self.block_root,
            block,
            blob_data,
            blobs_available_timestamp,
            spec: spec.clone(),
        };

        self.span.in_scope(|| {
            debug!("Block and all data components are available");
        });
        Ok(Some(AvailableExecutedBlock::new(
            available_block,
            import_data,
            payload_verification_outcome,
        )))
    }

    /// Returns an empty `PendingComponents` object with the given block root.
    pub fn empty(block_root: Hash256, max_len: usize) -> Self {
        let span = debug_span!(parent: None, SPAN_PENDING_COMPONENTS, %block_root);
        let _guard = span.clone().entered();
        Self {
            block_root,
            verified_blobs: RuntimeFixedVector::new(vec![None; max_len]),
            verified_data_columns: vec![],
            block: None,
            reconstruction_started: false,
            span,
        }
    }

    /// Returns the epoch of:
    /// - The block if it is cached
    /// - The first available blob
    /// - The first data column
    ///   Otherwise, returns None
    pub fn epoch(&self) -> Option<Epoch> {
        // Get epoch from cached block
        if let Some(block) = &self.block {
            return Some(block.as_block().epoch());
        }

        // Or, get epoch from first available blob
        if let Some(blob) = self.verified_blobs.iter().flatten().next() {
            return Some(blob.as_blob().slot().epoch(E::slots_per_epoch()));
        }

        // Or, get epoch from first data column
        if let Some(data_column) = self.verified_data_columns.first() {
            return Some(data_column.as_data_column().epoch());
        }

        None
    }

    pub fn status_str(&self, num_expected_columns_opt: Option<usize>) -> String {
        let block_count = if self.block.is_some() { 1 } else { 0 };
        if let Some(num_expected_columns) = num_expected_columns_opt {
            format!(
                "block {} data_columns {}/{}",
                block_count,
                self.verified_data_columns.len(),
                num_expected_columns
            )
        } else {
            let num_expected_blobs = if let Some(block) = &self.block {
                &block.num_blobs_expected().to_string()
            } else {
                "?"
            };
            format!(
                "block {} blobs {}/{}",
                block_count,
                self.verified_blobs.iter().flatten().count(),
                num_expected_blobs
            )
        }
    }
}

/// This is the main struct for this module. Outside methods should
/// interact with the cache through this.
pub struct DataAvailabilityCheckerInner<T: BeaconChainTypes> {
    /// Contains all the data we keep in memory, protected by an RwLock
    critical: RwLock<LruCache<Hash256, PendingComponents<T::EthSpec>>>,
    /// This cache holds a limited number of states in memory and reconstructs them
    /// from disk when necessary. This is necessary until we merge tree-states
    state_cache: StateLRUCache<T>,
    custody_context: Arc<CustodyContext<T::EthSpec>>,
    spec: Arc<ChainSpec>,
}

// This enum is only used internally within the crate in the reconstruction function to improve
// readability, so it's OK to not box the variant value, and it shouldn't impact memory much with
// the current usage, as it's deconstructed immediately.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ReconstructColumnsDecision<E: EthSpec> {
    Yes(Vec<KzgVerifiedCustodyDataColumn<E>>),
    No(&'static str),
}

impl<T: BeaconChainTypes> DataAvailabilityCheckerInner<T> {
    pub fn new(
        capacity: NonZeroUsize,
        beacon_store: BeaconStore<T>,
        custody_context: Arc<CustodyContext<T::EthSpec>>,
        spec: Arc<ChainSpec>,
    ) -> Result<Self, AvailabilityCheckError> {
        Ok(Self {
            critical: RwLock::new(LruCache::new(capacity)),
            state_cache: StateLRUCache::new(beacon_store, spec.clone()),
            custody_context,
            spec,
        })
    }

    /// Returns true if the block root is known, without altering the LRU ordering
    pub fn get_cached_block(&self, block_root: &Hash256) -> Option<BlockProcessStatus<T::EthSpec>> {
        self.critical
            .read()
            .peek(block_root)
            .and_then(|pending_components| {
                pending_components.block.as_ref().map(|block| match block {
                    CachedBlock::PreExecution(b, source) => {
                        BlockProcessStatus::NotValidated(b.clone(), *source)
                    }
                    CachedBlock::Executed(b) => {
                        BlockProcessStatus::ExecutionValidated(b.block_cloned())
                    }
                })
            })
    }

    /// Fetch a blob from the cache without affecting the LRU ordering
    pub fn peek_blob(
        &self,
        blob_id: &BlobIdentifier,
    ) -> Result<Option<Arc<BlobSidecar<T::EthSpec>>>, AvailabilityCheckError> {
        if let Some(pending_components) = self.critical.read().peek(&blob_id.block_root) {
            Ok(pending_components
                .verified_blobs
                .get(blob_id.index as usize)
                .ok_or(AvailabilityCheckError::BlobIndexInvalid(blob_id.index))?
                .as_ref()
                .map(|blob| blob.clone_blob()))
        } else {
            Ok(None)
        }
    }

    /// Fetch data columns of a given `block_root` from the cache without affecting the LRU ordering
    pub fn peek_data_columns(
        &self,
        block_root: Hash256,
    ) -> Option<DataColumnSidecarList<T::EthSpec>> {
        self.critical
            .read()
            .peek(&block_root)
            .map(|pending_components| {
                pending_components
                    .verified_data_columns
                    .iter()
                    .map(|col| col.clone_arc())
                    .collect()
            })
    }

    pub fn peek_pending_components<R, F: FnOnce(Option<&PendingComponents<T::EthSpec>>) -> R>(
        &self,
        block_root: &Hash256,
        f: F,
    ) -> R {
        f(self.critical.read().peek(block_root))
    }

    /// Puts the KZG verified blobs into the availability cache as pending components.
    pub fn put_kzg_verified_blobs<I: IntoIterator<Item = KzgVerifiedBlob<T::EthSpec>>>(
        &self,
        block_root: Hash256,
        kzg_verified_blobs: I,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let mut kzg_verified_blobs = kzg_verified_blobs.into_iter().peekable();

        let Some(epoch) = kzg_verified_blobs
            .peek()
            .map(|verified_blob| verified_blob.as_blob().epoch())
        else {
            // Verified blobs list should be non-empty.
            return Err(AvailabilityCheckError::Unexpected("empty blobs".to_owned()));
        };

        let mut fixed_blobs =
            RuntimeFixedVector::new(vec![None; self.spec.max_blobs_per_block(epoch) as usize]);

        for blob in kzg_verified_blobs {
            if let Some(blob_opt) = fixed_blobs.get_mut(blob.blob_index() as usize) {
                *blob_opt = Some(blob);
            }
        }
        let pending_components =
            self.update_or_insert_pending_components(block_root, epoch, |pending_components| {
                pending_components.merge_blobs(fixed_blobs);
                Ok(())
            })?;

        pending_components.span.in_scope(|| {
            debug!(
                component = "blobs",
                status = pending_components.status_str(None),
                "Component added to data availability checker"
            );
        });

        self.check_availability_and_cache_components(block_root, pending_components, None)
    }

    #[allow(clippy::type_complexity)]
    pub fn put_kzg_verified_data_columns<
        I: IntoIterator<Item = KzgVerifiedCustodyDataColumn<T::EthSpec>>,
    >(
        &self,
        block_root: Hash256,
        kzg_verified_data_columns: I,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let mut kzg_verified_data_columns = kzg_verified_data_columns.into_iter().peekable();
        let Some(epoch) = kzg_verified_data_columns
            .peek()
            .map(|verified_blob| verified_blob.as_data_column().epoch())
        else {
            // No columns are processed. This can occur if all received columns were filtered out
            // before this point, e.g. due to a CGC change that caused extra columns to be downloaded
            // // before the new CGC took effect.
            // Return `Ok` without marking the block as available.
            return Ok(Availability::MissingComponents(block_root));
        };

        let pending_components =
            self.update_or_insert_pending_components(block_root, epoch, |pending_components| {
                pending_components.merge_data_columns(kzg_verified_data_columns)
            })?;

        let num_expected_columns = self
            .custody_context
            .num_of_data_columns_to_sample(epoch, &self.spec);

        pending_components.span.in_scope(|| {
            debug!(
                component = "data_columns",
                status = pending_components.status_str(Some(num_expected_columns)),
                "Component added to data availability checker"
            );
        });

        self.check_availability_and_cache_components(
            block_root,
            pending_components,
            Some(num_expected_columns),
        )
    }

    fn check_availability_and_cache_components(
        &self,
        block_root: Hash256,
        pending_components: MappedRwLockReadGuard<'_, PendingComponents<T::EthSpec>>,
        num_expected_columns_opt: Option<usize>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        if let Some(available_block) = pending_components.make_available(
            &self.spec,
            num_expected_columns_opt,
            |block, span| self.state_cache.recover_pending_executed_block(block, span),
        )? {
            // Explicitly drop read lock before acquiring write lock
            drop(pending_components);
            if let Some(components) = self.critical.write().get_mut(&block_root) {
                // Clean up span now that block is available
                components.span = Span::none();
            }

            // We never remove the pending components manually to avoid race conditions.
            // This ensures components remain available during and right after block import,
            // preventing a race condition where a component was removed after the block was
            // imported, but re-inserted immediately, causing partial pending components to be
            // stored and served to peers.
            // Components are only removed via LRU eviction as finality advances.
            Ok(Availability::Available(Box::new(available_block)))
        } else {
            Ok(Availability::MissingComponents(block_root))
        }
    }

    /// Updates or inserts a new `PendingComponents` if it doesn't exist, and then apply the
    /// `update_fn` while holding the write lock.
    ///
    /// Once the update is complete, the write lock is downgraded and a read guard with a
    /// reference of the updated `PendingComponents` is returned.
    fn update_or_insert_pending_components<F>(
        &self,
        block_root: Hash256,
        epoch: Epoch,
        update_fn: F,
    ) -> Result<MappedRwLockReadGuard<'_, PendingComponents<T::EthSpec>>, AvailabilityCheckError>
    where
        F: FnOnce(&mut PendingComponents<T::EthSpec>) -> Result<(), AvailabilityCheckError>,
    {
        let mut write_lock = self.critical.write();

        {
            let pending_components = write_lock.get_or_insert_mut(block_root, || {
                PendingComponents::empty(block_root, self.spec.max_blobs_per_block(epoch) as usize)
            });
            update_fn(pending_components)?
        }

        RwLockReadGuard::try_map(RwLockWriteGuard::downgrade(write_lock), |cache| {
            cache.peek(&block_root)
        })
        .map_err(|_| {
            AvailabilityCheckError::Unexpected("pending components should exist".to_string())
        })
    }

    /// Check whether data column reconstruction should be attempted.
    ///
    /// Potentially trigger reconstruction if all the following satisfy:
    ///  - Our custody requirement is more than 50% of total columns,
    ///  - We haven't received all required columns
    ///  - Reconstruction hasn't been started for the block
    ///
    /// If reconstruction is required, returns `PendingComponents` which contains the
    /// components to be used as inputs to reconstruction, otherwise returns a `reason`.
    pub fn check_and_set_reconstruction_started(
        &self,
        block_root: &Hash256,
    ) -> ReconstructColumnsDecision<T::EthSpec> {
        let mut write_lock = self.critical.write();
        let Some(pending_components) = write_lock.get_mut(block_root) else {
            // Block may have been imported as it does not exist in availability cache.
            return ReconstructColumnsDecision::No("block already imported");
        };

        let Some(epoch) = pending_components
            .verified_data_columns
            .first()
            .map(|c| c.as_data_column().epoch())
        else {
            return ReconstructColumnsDecision::No("not enough columns");
        };

        let total_column_count = T::EthSpec::number_of_columns();
        let sampling_column_count = self
            .custody_context
            .num_of_data_columns_to_sample(epoch, &self.spec);
        let received_column_count = pending_components.verified_data_columns.len();

        if pending_components.reconstruction_started {
            return ReconstructColumnsDecision::No("already started");
        }
        if received_column_count >= sampling_column_count {
            return ReconstructColumnsDecision::No("all sampling columns received");
        }
        if received_column_count < total_column_count / 2 {
            return ReconstructColumnsDecision::No("not enough columns");
        }

        pending_components.reconstruction_started = true;
        ReconstructColumnsDecision::Yes(pending_components.verified_data_columns.clone())
    }

    /// This could mean some invalid data columns made it through to the `DataAvailabilityChecker`.
    /// In this case, we remove all data columns in `PendingComponents`, reset reconstruction
    /// status so that we can attempt to retrieve columns from peers again.
    pub fn handle_reconstruction_failure(&self, block_root: &Hash256) {
        if let Some(pending_components_mut) = self.critical.write().get_mut(block_root) {
            pending_components_mut.verified_data_columns = vec![];
            pending_components_mut.reconstruction_started = false;
        }
    }

    /// Inserts a pre executed block into the cache.
    /// - This does NOT trigger the availability check as the block still needs to be executed.
    /// - This does NOT override an existing cached block to avoid overwriting an executed block.
    pub fn put_pre_execution_block(
        &self,
        block_root: Hash256,
        block: Arc<SignedBeaconBlock<T::EthSpec>>,
        source: BlockImportSource,
    ) -> Result<(), AvailabilityCheckError> {
        let epoch = block.epoch();
        let pending_components =
            self.update_or_insert_pending_components(block_root, epoch, |pending_components| {
                pending_components.insert_pre_execution_block(block, source);
                Ok(())
            })?;

        let num_expected_columns_opt = self.get_num_expected_columns(epoch);

        pending_components.span.in_scope(|| {
            debug!(
                component = "pre execution block",
                status = pending_components.status_str(num_expected_columns_opt),
                "Component added to data availability checker"
            );
        });

        Ok(())
    }

    /// Removes a pre-execution block from the cache.
    /// This does NOT remove an existing executed block.
    pub fn remove_pre_execution_block(&self, block_root: &Hash256) {
        // The read lock is immediately dropped so we can safely remove the block from the cache.
        if let Some(BlockProcessStatus::NotValidated(_, _)) = self.get_cached_block(block_root) {
            self.critical.write().pop(block_root);
        }
    }

    /// Check if we have all the blobs for a block. If we do, return the Availability variant that
    /// triggers import of the block.
    pub fn put_executed_block(
        &self,
        executed_block: AvailabilityPendingExecutedBlock<T::EthSpec>,
    ) -> Result<Availability<T::EthSpec>, AvailabilityCheckError> {
        let epoch = executed_block.as_block().epoch();
        let block_root = executed_block.import_data.block_root;

        // register the block to get the diet block
        let diet_executed_block = self
            .state_cache
            .register_pending_executed_block(executed_block);

        let pending_components =
            self.update_or_insert_pending_components(block_root, epoch, |pending_components| {
                pending_components.merge_block(diet_executed_block);
                Ok(())
            })?;

        let num_expected_columns_opt = self.get_num_expected_columns(epoch);

        pending_components.span.in_scope(|| {
            debug!(
                component = "block",
                status = pending_components.status_str(num_expected_columns_opt),
                "Component added to data availability checker"
            );
        });

        self.check_availability_and_cache_components(
            block_root,
            pending_components,
            num_expected_columns_opt,
        )
    }

    fn get_num_expected_columns(&self, epoch: Epoch) -> Option<usize> {
        if self.spec.is_peer_das_enabled_for_epoch(epoch) {
            let num_of_column_samples = self
                .custody_context
                .num_of_data_columns_to_sample(epoch, &self.spec);
            Some(num_of_column_samples)
        } else {
            None
        }
    }

    /// maintain the cache
    pub fn do_maintenance(&self, cutoff_epoch: Epoch) -> Result<(), AvailabilityCheckError> {
        // clean up any lingering states in the state cache
        self.state_cache.do_maintenance(cutoff_epoch);

        // Collect keys of pending blocks from a previous epoch to cutoff
        let mut write_lock = self.critical.write();
        let mut keys_to_remove = vec![];
        for (key, value) in write_lock.iter() {
            if let Some(epoch) = value.epoch()
                && epoch < cutoff_epoch
            {
                keys_to_remove.push(*key);
            }
        }
        // Now remove keys
        for key in keys_to_remove {
            write_lock.pop(&key);
        }

        Ok(())
    }

    #[cfg(test)]
    /// get the state cache for inspection (used only for tests)
    pub fn state_lru_cache(&self) -> &StateLRUCache<T> {
        &self.state_cache
    }

    /// Number of states stored in memory in the cache.
    pub fn state_cache_size(&self) -> usize {
        self.state_cache.lru_cache().read().len()
    }

    /// Number of pending component entries in memory in the cache.
    pub fn block_cache_size(&self) -> usize {
        self.critical.read().len()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::test_utils::generate_data_column_indices_rand_order;
    use crate::{
        blob_verification::GossipVerifiedBlob,
        block_verification::PayloadVerificationOutcome,
        block_verification_types::{AsBlock, BlockImportData},
        custody_context::NodeCustodyType,
        data_availability_checker::STATE_LRU_CAPACITY_NON_ZERO,
        test_utils::{BaseHarnessType, BeaconChainHarness, DiskHarnessType},
    };
    use fork_choice::PayloadVerificationStatus;
    use logging::create_test_tracing_subscriber;
    use state_processing::ConsensusContext;
    use std::collections::VecDeque;
    use store::{HotColdDB, ItemStore, StoreConfig, database::interface::BeaconNodeBackend};
    use tempfile::{TempDir, tempdir};
    use tracing::{debug_span, info};
    use types::non_zero_usize::new_non_zero_usize;
    use types::{ExecPayload, MinimalEthSpec};

    const LOW_VALIDATOR_COUNT: usize = 32;
    const STATE_LRU_CAPACITY: usize = STATE_LRU_CAPACITY_NON_ZERO.get();

    fn get_store_with_spec<E: EthSpec>(
        db_path: &TempDir,
        spec: Arc<ChainSpec>,
    ) -> Arc<HotColdDB<E, BeaconNodeBackend<E>, BeaconNodeBackend<E>>> {
        let hot_path = db_path.path().join("hot_db");
        let cold_path = db_path.path().join("cold_db");
        let blobs_path = db_path.path().join("blobs_db");
        let config = StoreConfig::default();

        HotColdDB::open(
            &hot_path,
            &cold_path,
            &blobs_path,
            |_, _, _| Ok(()),
            config,
            spec,
        )
        .expect("disk store should initialize")
    }

    // get a beacon chain harness advanced to just before deneb fork
    async fn get_deneb_chain<E: EthSpec>(
        db_path: &TempDir,
    ) -> BeaconChainHarness<DiskHarnessType<E>> {
        let altair_fork_epoch = Epoch::new(1);
        let bellatrix_fork_epoch = Epoch::new(2);
        let bellatrix_fork_slot = bellatrix_fork_epoch.start_slot(E::slots_per_epoch());
        let capella_fork_epoch = Epoch::new(3);
        let deneb_fork_epoch = Epoch::new(4);
        let deneb_fork_slot = deneb_fork_epoch.start_slot(E::slots_per_epoch());

        let mut spec = E::default_spec();
        spec.altair_fork_epoch = Some(altair_fork_epoch);
        spec.bellatrix_fork_epoch = Some(bellatrix_fork_epoch);
        spec.capella_fork_epoch = Some(capella_fork_epoch);
        spec.deneb_fork_epoch = Some(deneb_fork_epoch);
        let spec = Arc::new(spec);

        let chain_store = get_store_with_spec::<E>(db_path, spec.clone());
        let validators_keypairs =
            types::test_utils::generate_deterministic_keypairs(LOW_VALIDATOR_COUNT);
        let harness = BeaconChainHarness::builder(E::default())
            .spec(spec.clone())
            .keypairs(validators_keypairs)
            .fresh_disk_store(chain_store)
            .mock_execution_layer()
            .build();

        // go to bellatrix slot
        harness.extend_to_slot(bellatrix_fork_slot).await;
        let bellatrix_head = &harness.chain.head_snapshot().beacon_block;
        assert!(bellatrix_head.as_bellatrix().is_ok());
        assert_eq!(bellatrix_head.slot(), bellatrix_fork_slot);
        assert!(
            bellatrix_head
                .message()
                .body()
                .execution_payload()
                .unwrap()
                .is_default_with_empty_roots(),
            "Bellatrix head is default payload"
        );
        // Trigger the terminal PoW block.
        harness
            .execution_block_generator()
            .move_to_terminal_block()
            .unwrap();
        // go right before deneb slot
        harness.extend_to_slot(deneb_fork_slot - 1).await;

        harness
    }

    async fn availability_pending_block<E, Hot, Cold>(
        harness: &BeaconChainHarness<BaseHarnessType<E, Hot, Cold>>,
    ) -> (
        AvailabilityPendingExecutedBlock<E>,
        Vec<GossipVerifiedBlob<BaseHarnessType<E, Hot, Cold>>>,
    )
    where
        E: EthSpec,
        Hot: ItemStore<E>,
        Cold: ItemStore<E>,
    {
        let chain = &harness.chain;
        let head = chain.head_snapshot();
        let parent_state = head.beacon_state.clone();

        let target_slot = chain.slot().expect("should get slot") + 1;
        let parent_root = head.beacon_block_root;
        let parent_block = chain
            .get_blinded_block(&parent_root)
            .expect("should get block")
            .expect("should have block");

        let (signed_beacon_block_hash, (block, maybe_blobs), state) = harness
            .add_block_at_slot(target_slot, parent_state)
            .await
            .expect("should add block");
        let block_root = signed_beacon_block_hash.into();
        assert_eq!(
            block_root,
            block.canonical_root(),
            "block root should match"
        );

        // log kzg commitments
        info!("printing kzg commitments");
        for comm in Vec::from(
            block
                .message()
                .body()
                .blob_kzg_commitments()
                .expect("should be deneb fork")
                .clone(),
        ) {
            info!(commitment = ?comm, "kzg commitment");
        }
        info!("done printing kzg commitments");

        let gossip_verified_blobs = if let Some((kzg_proofs, blobs)) = maybe_blobs {
            let sidecars =
                BlobSidecar::build_sidecars(blobs, &block, kzg_proofs, &chain.spec).unwrap();
            Vec::from(sidecars)
                .into_iter()
                .map(|sidecar| {
                    let subnet = sidecar.index;
                    GossipVerifiedBlob::new(sidecar, subnet, &harness.chain)
                        .expect("should validate blob")
                })
                .collect()
        } else {
            vec![]
        };

        let slot = block.slot();
        let consensus_context = ConsensusContext::<E>::new(slot);
        let import_data: BlockImportData<E> = BlockImportData {
            block_root,
            state,
            parent_block,
            consensus_context,
        };

        let payload_verification_outcome = PayloadVerificationOutcome {
            payload_verification_status: PayloadVerificationStatus::Verified,
            is_valid_merge_transition_block: false,
        };

        let availability_pending_block = AvailabilityPendingExecutedBlock {
            block,
            import_data,
            payload_verification_outcome,
        };

        (availability_pending_block, gossip_verified_blobs)
    }

    async fn setup_harness_and_cache<E, T>(
        capacity: usize,
    ) -> (
        BeaconChainHarness<DiskHarnessType<E>>,
        Arc<DataAvailabilityCheckerInner<T>>,
        TempDir,
    )
    where
        E: EthSpec,
        T: BeaconChainTypes<
                HotStore = BeaconNodeBackend<E>,
                ColdStore = BeaconNodeBackend<E>,
                EthSpec = E,
            >,
    {
        create_test_tracing_subscriber();
        let chain_db_path = tempdir().expect("should get temp dir");
        let harness = get_deneb_chain(&chain_db_path).await;
        let spec = harness.spec.clone();
        let test_store = harness.chain.store.clone();
        let capacity_non_zero = new_non_zero_usize(capacity);
        let custody_context = Arc::new(CustodyContext::new(
            NodeCustodyType::Fullnode,
            generate_data_column_indices_rand_order::<E>(),
            &spec,
        ));
        let cache = Arc::new(
            DataAvailabilityCheckerInner::<T>::new(
                capacity_non_zero,
                test_store,
                custody_context,
                spec.clone(),
            )
            .expect("should create cache"),
        );
        (harness, cache, chain_db_path)
    }

    #[tokio::test]
    async fn overflow_cache_test_insert_components() {
        type E = MinimalEthSpec;
        type T = DiskHarnessType<E>;
        let capacity = 4;
        let (harness, cache, _path) = setup_harness_and_cache::<E, T>(capacity).await;

        let (pending_block, blobs) = availability_pending_block(&harness).await;
        let root = pending_block.import_data.block_root;

        let blobs_expected = pending_block.num_blobs_expected();
        assert_eq!(
            blobs.len(),
            blobs_expected,
            "should have expected number of blobs"
        );
        assert!(cache.critical.read().is_empty(), "cache should be empty");
        let availability = cache
            .put_executed_block(pending_block)
            .expect("should put block");
        if blobs_expected == 0 {
            assert!(
                matches!(availability, Availability::Available(_)),
                "block doesn't have blobs, should be available"
            );
            assert_eq!(
                cache.critical.read().len(),
                1,
                "cache should still have block as it hasn't been imported yet"
            );
        } else {
            assert!(
                matches!(availability, Availability::MissingComponents(_)),
                "should be pending blobs"
            );
            assert_eq!(
                cache.critical.read().len(),
                1,
                "cache should have one block"
            );
            assert!(
                cache.critical.read().peek(&root).is_some(),
                "newly inserted block should exist in memory"
            );
        }

        let mut kzg_verified_blobs = Vec::new();
        for (blob_index, gossip_blob) in blobs.into_iter().enumerate() {
            kzg_verified_blobs.push(gossip_blob.into_inner());
            let availability = cache
                .put_kzg_verified_blobs(root, kzg_verified_blobs.clone())
                .expect("should put blob");
            if blob_index == blobs_expected - 1 {
                assert!(matches!(availability, Availability::Available(_)));
            } else {
                assert!(matches!(availability, Availability::MissingComponents(_)));
                assert_eq!(cache.critical.read().len(), 1);
            }
        }

        let (pending_block, blobs) = availability_pending_block(&harness).await;
        let blobs_expected = pending_block.num_blobs_expected();
        assert_eq!(
            blobs.len(),
            blobs_expected,
            "should have expected number of blobs"
        );
        let root = pending_block.import_data.block_root;
        let mut kzg_verified_blobs = vec![];
        for gossip_blob in blobs {
            kzg_verified_blobs.push(gossip_blob.into_inner());
            let availability = cache
                .put_kzg_verified_blobs(root, kzg_verified_blobs.clone())
                .expect("should put blob");
            assert!(
                matches!(availability, Availability::MissingComponents(_)),
                "should be pending block"
            );
            assert_eq!(
                cache.critical.read().len(),
                2,
                "cache should have two blocks now"
            );
        }
        let availability = cache
            .put_executed_block(pending_block)
            .expect("should put block");
        assert!(
            matches!(availability, Availability::Available(_)),
            "block should be available: {:?}",
            availability
        );
        assert!(
            cache.critical.read().len() == 2,
            "cache should still have available block"
        );
    }

    #[tokio::test]
    // ensure the state cache keeps memory usage low and that it can properly recover states
    // THIS TEST CAN BE DELETED ONCE TREE STATES IS MERGED AND WE RIP OUT THE STATE CACHE
    async fn overflow_cache_test_state_cache() {
        type E = MinimalEthSpec;
        type T = DiskHarnessType<E>;
        let capacity = STATE_LRU_CAPACITY * 2;
        let (harness, cache, _path) = setup_harness_and_cache::<E, T>(capacity).await;

        let mut pending_blocks = VecDeque::new();
        let mut states = Vec::new();
        let mut state_roots = Vec::new();
        // Get enough blocks to fill the cache to capacity, ensuring all blocks have blobs
        while pending_blocks.len() < capacity {
            let (mut pending_block, _) = availability_pending_block(&harness).await;
            if pending_block.num_blobs_expected() == 0 {
                // we need blocks with blobs
                continue;
            }
            let state_root = pending_block.import_data.state.canonical_root().unwrap();
            states.push(pending_block.import_data.state.clone());
            pending_blocks.push_back(pending_block);
            state_roots.push(state_root);
        }

        let state_cache = cache.state_lru_cache().lru_cache();
        let mut pushed_diet_blocks = VecDeque::new();

        for i in 0..capacity {
            let pending_block = pending_blocks.pop_front().expect("should have block");
            let block_root = pending_block.as_block().canonical_root();

            assert_eq!(
                state_cache.read().len(),
                std::cmp::min(i, STATE_LRU_CAPACITY),
                "state cache should be empty at start"
            );

            if i >= STATE_LRU_CAPACITY {
                let lru_root = state_roots[i - STATE_LRU_CAPACITY];
                assert_eq!(
                    state_cache.read().peek_lru().map(|(root, _)| root),
                    Some(&lru_root),
                    "lru block should be in cache"
                );
            }

            // put the block in the cache
            let availability = cache
                .put_executed_block(pending_block)
                .expect("should put block");

            // grab the diet block from the cache for later testing
            let diet_block = cache
                .critical
                .read()
                .peek(&block_root)
                .and_then(|pending_components| pending_components.get_diet_block().cloned())
                .expect("should exist");
            pushed_diet_blocks.push_back(diet_block);

            // should be unavailable since we made sure all blocks had blobs
            assert!(
                matches!(availability, Availability::MissingComponents(_)),
                "should be pending blobs"
            );

            if i >= STATE_LRU_CAPACITY {
                let evicted_index = i - STATE_LRU_CAPACITY;
                let evicted_root = state_roots[evicted_index];
                assert!(
                    state_cache.read().peek(&evicted_root).is_none(),
                    "lru root should be evicted"
                );
                // get the diet block via direct conversion (testing only)
                let diet_block = pushed_diet_blocks.pop_front().expect("should have block");
                // reconstruct the pending block by replaying the block on the parent state
                let recovered_pending_block = cache
                    .state_lru_cache()
                    .recover_pending_executed_block(diet_block, &debug_span!("test"))
                    .expect("should reconstruct pending block");

                // assert the recovered state is the same as the original
                assert_eq!(
                    recovered_pending_block.import_data.state, states[evicted_index],
                    "recovered state should be the same as the original"
                );
            }
        }

        // now check the last block
        let last_block = pushed_diet_blocks.pop_back().expect("should exist").clone();
        // the state should still be in the cache
        assert!(
            state_cache
                .read()
                .peek(&last_block.as_block().state_root())
                .is_some(),
            "last block state should still be in cache"
        );
        // get the diet block via direct conversion (testing only)
        let diet_block = last_block.clone();
        // recover the pending block from the cache
        let recovered_pending_block = cache
            .state_lru_cache()
            .recover_pending_executed_block(diet_block, &debug_span!("test"))
            .expect("should reconstruct pending block");
        // assert the recovered state is the same as the original
        assert_eq!(
            Some(&recovered_pending_block.import_data.state),
            states.last(),
            "recovered state should be the same as the original"
        );
    }
}

#[cfg(test)]
mod pending_components_tests {
    use super::*;
    use crate::PayloadVerificationOutcome;
    use crate::block_verification_types::BlockImportData;
    use crate::test_utils::{NumBlobs, generate_rand_block_and_blobs, test_spec};
    use fork_choice::PayloadVerificationStatus;
    use kzg::KzgCommitment;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use state_processing::ConsensusContext;
    use types::test_utils::TestRandom;
    use types::{
        BeaconState, FixedBytesExtended, ForkName, MainnetEthSpec, SignedBeaconBlock, Slot,
    };

    type E = MainnetEthSpec;

    type Setup<E> = (
        SignedBeaconBlock<E>,
        RuntimeFixedVector<Option<Arc<BlobSidecar<E>>>>,
        RuntimeFixedVector<Option<Arc<BlobSidecar<E>>>>,
        usize,
    );

    pub fn pre_setup() -> Setup<E> {
        let mut rng = StdRng::seed_from_u64(0xDEADBEEF0BAD5EEDu64);
        let spec = test_spec::<E>();
        let (block, blobs_vec) =
            generate_rand_block_and_blobs::<E>(ForkName::Deneb, NumBlobs::Random, &mut rng, &spec);
        let max_len = spec.max_blobs_per_block(block.epoch()) as usize;
        let mut blobs: RuntimeFixedVector<Option<Arc<BlobSidecar<E>>>> =
            RuntimeFixedVector::default(max_len);

        for blob in blobs_vec {
            if let Some(b) = blobs.get_mut(blob.index as usize) {
                *b = Some(Arc::new(blob));
            }
        }

        let mut invalid_blobs: RuntimeFixedVector<Option<Arc<BlobSidecar<E>>>> =
            RuntimeFixedVector::default(max_len);
        for (index, blob) in blobs.iter().enumerate() {
            if let Some(invalid_blob) = blob {
                let mut blob_copy = invalid_blob.as_ref().clone();
                blob_copy.kzg_commitment = KzgCommitment::random_for_test(&mut rng);
                *invalid_blobs.get_mut(index).unwrap() = Some(Arc::new(blob_copy));
            }
        }

        (block, blobs, invalid_blobs, max_len)
    }

    type PendingComponentsSetup<E> = (
        DietAvailabilityPendingExecutedBlock<E>,
        RuntimeFixedVector<Option<KzgVerifiedBlob<E>>>,
        RuntimeFixedVector<Option<KzgVerifiedBlob<E>>>,
    );

    pub fn setup_pending_components(
        block: SignedBeaconBlock<E>,
        valid_blobs: RuntimeFixedVector<Option<Arc<BlobSidecar<E>>>>,
        invalid_blobs: RuntimeFixedVector<Option<Arc<BlobSidecar<E>>>>,
    ) -> PendingComponentsSetup<E> {
        let blobs = RuntimeFixedVector::new(
            valid_blobs
                .iter()
                .map(|blob_opt| {
                    blob_opt
                        .as_ref()
                        .map(|blob| KzgVerifiedBlob::__assumed_valid(blob.clone()))
                })
                .collect::<Vec<_>>(),
        );
        let invalid_blobs = RuntimeFixedVector::new(
            invalid_blobs
                .iter()
                .map(|blob_opt| {
                    blob_opt
                        .as_ref()
                        .map(|blob| KzgVerifiedBlob::__assumed_valid(blob.clone()))
                })
                .collect::<Vec<_>>(),
        );
        let dummy_parent = block.clone_as_blinded();
        let block = AvailabilityPendingExecutedBlock {
            block: Arc::new(block),
            import_data: BlockImportData {
                block_root: Default::default(),
                state: BeaconState::new(0, Default::default(), &ChainSpec::minimal()),
                parent_block: dummy_parent,
                consensus_context: ConsensusContext::new(Slot::new(0)),
            },
            payload_verification_outcome: PayloadVerificationOutcome {
                payload_verification_status: PayloadVerificationStatus::Verified,
                is_valid_merge_transition_block: false,
            },
        };
        (block.into(), blobs, invalid_blobs)
    }

    pub fn assert_cache_consistent(cache: PendingComponents<E>, max_len: usize) {
        if let Some(cached_block) = &cache.block {
            let cached_block_commitments = cached_block.get_commitments();
            for index in 0..max_len {
                let block_commitment = cached_block_commitments.get(index).copied();
                let blob_commitment_opt = cache.get_cached_blobs().get(index).unwrap();
                let blob_commitment = blob_commitment_opt.as_ref().map(|b| *b.get_commitment());
                assert_eq!(block_commitment, blob_commitment);
            }
        } else {
            panic!("No cached block")
        }
    }

    pub fn assert_empty_blob_cache(cache: PendingComponents<E>) {
        for blob in cache.get_cached_blobs().iter() {
            assert!(blob.is_none());
        }
    }

    #[test]
    fn valid_block_invalid_blobs_valid_blobs() {
        let (block_commitments, blobs, random_blobs, max_len) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);
        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root, max_len);
        cache.merge_block(block_commitments);
        cache.merge_blobs(random_blobs);
        cache.merge_blobs(blobs);

        assert_cache_consistent(cache, max_len);
    }

    #[test]
    fn invalid_blobs_block_valid_blobs() {
        let (block_commitments, blobs, random_blobs, max_len) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);
        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root, max_len);
        cache.merge_blobs(random_blobs);
        cache.merge_block(block_commitments);
        cache.merge_blobs(blobs);

        assert_cache_consistent(cache, max_len);
    }

    #[test]
    fn invalid_blobs_valid_blobs_block() {
        let (block_commitments, blobs, random_blobs, max_len) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);

        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root, max_len);
        cache.merge_blobs(random_blobs);
        cache.merge_blobs(blobs);
        cache.merge_block(block_commitments);

        assert_empty_blob_cache(cache);
    }

    #[test]
    fn block_valid_blobs_invalid_blobs() {
        let (block_commitments, blobs, random_blobs, max_len) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);

        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root, max_len);
        cache.merge_block(block_commitments);
        cache.merge_blobs(blobs);
        cache.merge_blobs(random_blobs);

        assert_cache_consistent(cache, max_len);
    }

    #[test]
    fn valid_blobs_block_invalid_blobs() {
        let (block_commitments, blobs, random_blobs, max_len) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);

        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root, max_len);
        cache.merge_blobs(blobs);
        cache.merge_block(block_commitments);
        cache.merge_blobs(random_blobs);

        assert_cache_consistent(cache, max_len);
    }

    #[test]
    fn valid_blobs_invalid_blobs_block() {
        let (block_commitments, blobs, random_blobs, max_len) = pre_setup();
        let (block_commitments, blobs, random_blobs) =
            setup_pending_components(block_commitments, blobs, random_blobs);

        let block_root = Hash256::zero();
        let mut cache = <PendingComponents<E>>::empty(block_root, max_len);
        cache.merge_blobs(blobs);
        cache.merge_blobs(random_blobs);
        cache.merge_block(block_commitments);

        assert_cache_consistent(cache, max_len);
    }

    #[test]
    fn should_not_insert_pre_execution_block_if_executed_block_exists() {
        let (pre_execution_block, blobs, random_blobs, max_len) = pre_setup();
        let (executed_block, _blobs, _random_blobs) =
            setup_pending_components(pre_execution_block.clone(), blobs, random_blobs);

        let block_root = pre_execution_block.canonical_root();
        let mut pending_component = <PendingComponents<E>>::empty(block_root, max_len);

        let pre_execution_block = Arc::new(pre_execution_block);
        pending_component
            .insert_pre_execution_block(pre_execution_block.clone(), BlockImportSource::Gossip);
        assert!(
            matches!(
                pending_component.block,
                Some(CachedBlock::PreExecution(_, _))
            ),
            "pre execution block inserted"
        );

        pending_component.insert_executed_block(executed_block);
        assert!(
            matches!(pending_component.block, Some(CachedBlock::Executed(_))),
            "executed block inserted"
        );

        pending_component
            .insert_pre_execution_block(pre_execution_block, BlockImportSource::Gossip);
        assert!(
            matches!(pending_component.block, Some(CachedBlock::Executed(_))),
            "executed block should remain"
        );
    }
}
