use crate::block_verification_types::{MaybeAvailableBlock, RpcBlock};
use crate::data_availability_checker::{
    AvailabilityCheckError, AvailableBlock, AvailableBlockData,
};
use crate::{metrics, BeaconChain, BeaconChainTypes};
use itertools::Itertools;
use state_processing::{
    per_block_processing::ParallelSignatureSets,
    signature_sets::{block_proposal_signature_set_from_parts, Error as SignatureSetError},
};
use std::borrow::Cow;
use std::iter;
use std::time::Duration;
use store::metadata::DataColumnInfo;
use store::{AnchorInfo, BlobInfo, DBColumn, Error as StoreError, KeyValueStore, KeyValueStoreOp};
use strum::IntoStaticStr;
use tracing::debug;
use types::{ColumnIndex, FixedBytesExtended, Hash256, Slot};

/// Use a longer timeout on the pubkey cache.
///
/// It's ok if historical sync is stalled due to writes from forwards block processing.
const PUBKEY_CACHE_LOCK_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, IntoStaticStr)]
pub enum HistoricalBlockError {
    /// Block root mismatch, caller should retry with different blocks.
    MismatchedBlockRoot {
        block_slot: Slot,
        block_root: Hash256,
        expected_block_root: Hash256,
        oldest_block_parent: Hash256,
    },
    /// Bad signature, caller should retry with different blocks.
    InvalidSignature(String),
    /// One or more signatures in a BlobSidecar of an RpcBlock are invalid
    InvalidBlobsSignature(Vec<u64>),
    /// One or more signatures in a DataColumnSidecar of an RpcBlock are invalid
    InvalidDataColumnsSignature(Vec<ColumnIndex>),
    /// Unexpected error
    Unexpected(String),
    /// Transitory error, caller should retry with the same blocks.
    ValidatorPubkeyCacheTimeout,
    /// Logic error: should never occur.
    IndexOutOfBounds,
    /// Internal store error
    StoreError(StoreError),
    /// Faulty and internal AvailabilityCheckError
    AvailabilityCheckError(AvailabilityCheckError),
}

impl From<StoreError> for HistoricalBlockError {
    fn from(e: StoreError) -> Self {
        Self::StoreError(e)
    }
}

impl From<SignatureSetError> for HistoricalBlockError {
    fn from(err: SignatureSetError) -> Self {
        match err {
            // The encoding of the signature is invalid, peer fault
            e
            @ (SignatureSetError::SignatureInvalid(_) | SignatureSetError::BadBlsBytes { .. }) => {
                Self::InvalidSignature(format!("{e:?}"))
            }
            // All these variants are internal errors or unreachable for historical block paths,
            // which only check the proposer signature.
            // BadBlsBytes = Unreachable
            e @ (SignatureSetError::BeaconStateError(_)
            | SignatureSetError::ValidatorUnknown(_)
            | SignatureSetError::ValidatorPubkeyUnknown(_)
            | SignatureSetError::IncorrectBlockProposer { .. }
            | SignatureSetError::PublicKeyDecompressionFailed
            | SignatureSetError::InconsistentBlockFork(_)) => Self::Unexpected(format!("{e:?}")),
        }
    }
}

impl From<AvailabilityCheckError> for HistoricalBlockError {
    fn from(e: AvailabilityCheckError) -> Self {
        Self::AvailabilityCheckError(e)
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn assert_correct_historical_block_chain(
        &self,
        blocks: &[RpcBlock<T::EthSpec>],
    ) -> Result<(), HistoricalBlockError> {
        let anchor_info = self.store.get_anchor_info();
        let mut expected_block_root = anchor_info.oldest_block_parent;

        for block in blocks.iter().rev() {
            if block.as_block().slot() >= anchor_info.oldest_block_slot {
                continue;
            }

            if block.block_root() != expected_block_root {
                return Err(HistoricalBlockError::MismatchedBlockRoot {
                    block_slot: block.as_block().slot(),
                    block_root: block.block_root(),
                    expected_block_root,
                    oldest_block_parent: anchor_info.oldest_block_parent,
                });
            }

            expected_block_root = block.as_block().message().parent_root();
        }

        Ok(())
    }

    pub fn verify_and_import_historical_block_batch(
        &self,
        blocks: Vec<RpcBlock<T::EthSpec>>,
    ) -> Result<usize, HistoricalBlockError> {
        let anchor_info = self.store.get_anchor_info();

        // Take all blocks with slots less than the oldest block slot.
        let blocks_to_import = blocks
            .into_iter()
            .filter(|block| block.as_block().slot() < anchor_info.oldest_block_slot)
            .collect::<Vec<_>>();

        // First check that chain of blocks is correct
        self.assert_correct_historical_block_chain(&blocks_to_import)?;

        // Check that all data columns are present <- faulty failure if missing because we have
        // checked the block root is correct first.
        let available_blocks_to_import = self
            .data_availability_checker
            .verify_kzg_for_rpc_blocks(blocks_to_import)
            .and_then(|blocks| {
                blocks
                    .into_iter()
                    // RpcBlocks must always be Available, otherwise a data peer is faulty of
                    // malicious. `verify_kzg_for_rpc_blocks` returns errors for those cases, but we
                    // haven't updated its function signature. This code block can be deleted later
                    // bigger refactor.
                    .map(|maybe_available| match maybe_available {
                        MaybeAvailableBlock::Available(block) => Ok(block),
                        MaybeAvailableBlock::AvailabilityPending { .. } => Err(
                            AvailabilityCheckError::Unexpected("block not available".to_string()),
                        ),
                    })
                    .collect::<Result<Vec<_>, _>>()
            })?;

        self.import_historical_block_batch(available_blocks_to_import)
    }

    /// Store a batch of historical blocks in the database.
    ///
    /// The `blocks` should be given in slot-ascending order. One of the blocks should have a block
    /// root corresponding to the `oldest_block_parent` from the store's `AnchorInfo`.
    ///
    /// The block roots and proposer signatures are verified. If any block doesn't match the parent
    /// root listed in its successor, then the whole batch will be discarded and
    /// `MismatchedBlockRoot` will be returned. If any proposer signature is invalid then
    /// `SignatureSetError` or `InvalidSignature` will be returned.
    ///
    /// To align with sync we allow some excess blocks with slots greater than or equal to
    /// `oldest_block_slot` to be provided. They will be ignored without being checked.
    ///
    /// This function should not be called concurrently with any other function that mutates
    /// the anchor info (including this function itself). If a concurrent mutation occurs that
    /// would violate consistency then an `AnchorInfoConcurrentMutation` error will be returned.
    ///
    /// Return the number of blocks successfully imported.
    pub fn import_historical_block_batch(
        &self,
        mut blocks: Vec<AvailableBlock<T::EthSpec>>,
    ) -> Result<usize, HistoricalBlockError> {
        let anchor_info = self.store.get_anchor_info();
        let blob_info = self.store.get_blob_info();
        let data_column_info = self.store.get_data_column_info();

        // Take all blocks with slots less than the oldest block slot.
        let num_relevant = blocks.partition_point(|available_block| {
            available_block.block().slot() < anchor_info.oldest_block_slot
        });

        let total_blocks = blocks.len();
        blocks.truncate(num_relevant);
        let blocks_to_import = blocks;

        if blocks_to_import.len() != total_blocks {
            debug!(
                oldest_block_slot = %anchor_info.oldest_block_slot,
                total_blocks,
                ignored = total_blocks.saturating_sub(blocks_to_import.len()),
                "Ignoring some historic blocks"
            );
        }

        if blocks_to_import.is_empty() {
            return Ok(0);
        }

        let mut expected_block_root = anchor_info.oldest_block_parent;
        let mut prev_block_slot = anchor_info.oldest_block_slot;
        let mut new_oldest_blob_slot = blob_info.oldest_blob_slot;
        let mut new_oldest_data_column_slot = data_column_info.oldest_data_column_slot;

        let mut blob_batch = Vec::<KeyValueStoreOp>::new();
        let mut cold_batch = Vec::with_capacity(blocks_to_import.len());
        let mut hot_batch = Vec::with_capacity(blocks_to_import.len());
        let mut signed_blocks = Vec::with_capacity(blocks_to_import.len());

        for available_block in blocks_to_import.iter().cloned().rev() {
            let (block_root, block, block_data) = available_block.deconstruct();

            if !self.store.get_config().prune_payloads {
                // If prune-payloads is set to false, store the block which includes the execution payload
                self.store
                    .block_as_kv_store_ops(&block_root, (*block).clone(), &mut hot_batch)?;
            } else {
                let blinded_block = block.clone_as_blinded();
                // Store block in the hot database without payload.
                self.store.blinded_block_as_kv_store_ops(
                    &block_root,
                    &blinded_block,
                    &mut hot_batch,
                );
            }

            match &block_data {
                AvailableBlockData::NoData => {}
                AvailableBlockData::Blobs(..) => {
                    new_oldest_blob_slot = Some(block.slot());
                }
                AvailableBlockData::DataColumns(_) => {
                    new_oldest_data_column_slot = Some(block.slot());
                }
            }

            // Store the blobs or data columns too
            if let Some(op) = self
                .get_blobs_or_columns_store_op(block_root, block_data)
                .map_err(|e| {
                    HistoricalBlockError::StoreError(StoreError::DBError {
                        message: format!("get_blobs_or_columns_store_op error {e:?}"),
                    })
                })?
            {
                blob_batch.extend(self.store.convert_to_kv_batch(vec![op])?);
            }

            // Store block roots, including at all skip slots in the freezer DB.
            for slot in (block.slot().as_u64()..prev_block_slot.as_u64()).rev() {
                cold_batch.push(KeyValueStoreOp::PutKeyValue(
                    DBColumn::BeaconBlockRoots,
                    slot.to_be_bytes().to_vec(),
                    block_root.as_slice().to_vec(),
                ));
            }

            prev_block_slot = block.slot();
            expected_block_root = block.message().parent_root();
            signed_blocks.push(block);

            // If we've reached genesis, add the genesis block root to the batch for all slots
            // between 0 and the first block slot, and set the anchor slot to 0 to indicate
            // completion.
            if expected_block_root == self.genesis_block_root {
                let genesis_slot = self.spec.genesis_slot;
                for slot in genesis_slot.as_u64()..prev_block_slot.as_u64() {
                    cold_batch.push(KeyValueStoreOp::PutKeyValue(
                        DBColumn::BeaconBlockRoots,
                        slot.to_be_bytes().to_vec(),
                        self.genesis_block_root.as_slice().to_vec(),
                    ));
                }
                prev_block_slot = genesis_slot;
                expected_block_root = Hash256::zero();
                break;
            }
        }
        // these were pushed in reverse order so we reverse again
        signed_blocks.reverse();

        // Verify signatures in one batch, holding the pubkey cache lock for the shortest duration
        // possible. For each block fetch the parent root from its successor. Slicing from index 1
        // is safe because we've already checked that `blocks_to_import` is non-empty.
        let sig_timer = metrics::start_timer(&metrics::BACKFILL_SIGNATURE_TOTAL_TIMES);
        let setup_timer = metrics::start_timer(&metrics::BACKFILL_SIGNATURE_SETUP_TIMES);
        let pubkey_cache = self
            .validator_pubkey_cache
            .try_read_for(PUBKEY_CACHE_LOCK_TIMEOUT)
            .ok_or(HistoricalBlockError::ValidatorPubkeyCacheTimeout)?;
        let block_roots = signed_blocks
            .get(1..)
            .ok_or(HistoricalBlockError::IndexOutOfBounds)?
            .iter()
            .map(|block| block.parent_root())
            .chain(iter::once(anchor_info.oldest_block_parent));
        let signature_set = signed_blocks
            .iter()
            .zip_eq(block_roots)
            .filter(|&(_block, block_root)| (block_root != self.genesis_block_root))
            .map(|(block, block_root)| {
                block_proposal_signature_set_from_parts(
                    block,
                    Some(block_root),
                    block.message().proposer_index(),
                    &self.spec.fork_at_epoch(block.message().epoch()),
                    self.genesis_validators_root,
                    |validator_index| pubkey_cache.get(validator_index).cloned().map(Cow::Owned),
                    &self.spec,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map(ParallelSignatureSets::from)?;
        drop(pubkey_cache);
        drop(setup_timer);

        let verify_timer = metrics::start_timer(&metrics::BACKFILL_SIGNATURE_VERIFY_TIMES);
        if !signature_set.verify() {
            return Err(HistoricalBlockError::InvalidSignature("invalid".to_owned()));
        }
        drop(verify_timer);
        drop(sig_timer);

        // Check that the proposer signature in the blobs and data columns is the same as the
        // correct signature in the block.
        blocks_to_import
            .iter()
            .map(|block| {
                if let Err(indices) = block.match_block_and_blobs() {
                    return Err(HistoricalBlockError::InvalidBlobsSignature(indices));
                }
                if let Err(indices) = block.match_block_and_data_columns() {
                    return Err(HistoricalBlockError::InvalidDataColumnsSignature(indices));
                }
                Ok(())
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Write the I/O batches to disk, writing the blocks themselves first, as it's better
        // for the hot DB to contain extra blocks than for the cold DB to point to blocks that
        // do not exist.
        self.store.blobs_db.do_atomically(blob_batch)?;
        self.store.hot_db.do_atomically(hot_batch)?;
        self.store.cold_db.do_atomically(cold_batch)?;

        let mut anchor_and_blob_batch = Vec::with_capacity(3);

        // Update the blob info.
        if new_oldest_blob_slot != blob_info.oldest_blob_slot {
            if let Some(oldest_blob_slot) = new_oldest_blob_slot {
                let new_blob_info = BlobInfo {
                    oldest_blob_slot: Some(oldest_blob_slot),
                    ..blob_info.clone()
                };
                anchor_and_blob_batch.push(
                    self.store
                        .compare_and_set_blob_info(blob_info, new_blob_info)?,
                );
            }
        }

        // Update the data column info.
        if new_oldest_data_column_slot != data_column_info.oldest_data_column_slot {
            if let Some(oldest_data_column_slot) = new_oldest_data_column_slot {
                let new_data_column_info = DataColumnInfo {
                    oldest_data_column_slot: Some(oldest_data_column_slot),
                };
                anchor_and_blob_batch.push(
                    self.store
                        .compare_and_set_data_column_info(data_column_info, new_data_column_info)?,
                );
            }
        }

        // Update the anchor.
        let new_anchor = AnchorInfo {
            oldest_block_slot: prev_block_slot,
            oldest_block_parent: expected_block_root,
            ..anchor_info
        };
        let backfill_complete = new_anchor.block_backfill_complete(self.genesis_backfill_slot);
        anchor_and_blob_batch.push(
            self.store
                .compare_and_set_anchor_info(anchor_info, new_anchor)?,
        );
        self.store.hot_db.do_atomically(anchor_and_blob_batch)?;

        // If backfill has completed and the chain is configured to reconstruct historic states,
        // send a message to the background migrator instructing it to begin reconstruction.
        // This can only happen if we have backfilled all the way to genesis.
        if backfill_complete
            && self.genesis_backfill_slot == Slot::new(0)
            && self.config.reconstruct_historic_states
        {
            self.store_migrator.process_reconstruction();
        }

        Ok(num_relevant)
    }
}
