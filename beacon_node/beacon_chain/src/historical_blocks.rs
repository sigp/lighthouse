use crate::data_availability_checker::AvailableBlock;
use crate::{metrics, BeaconChain, BeaconChainTypes};
use itertools::Itertools;
use slog::debug;
use state_processing::{
    per_block_processing::ParallelSignatureSets,
    signature_sets::{block_proposal_signature_set_from_parts, Error as SignatureSetError},
};
use std::borrow::Cow;
use std::iter;
use std::time::Duration;
use store::metadata::DataColumnInfo;
use store::{
    get_key_for_col, AnchorInfo, BlobInfo, DBColumn, Error as StoreError, KeyValueStore,
    KeyValueStoreOp,
};
use strum::IntoStaticStr;
use types::{FixedBytesExtended, Hash256, Slot};

/// Use a longer timeout on the pubkey cache.
///
/// It's ok if historical sync is stalled due to writes from forwards block processing.
const PUBKEY_CACHE_LOCK_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, IntoStaticStr)]
pub enum HistoricalBlockError {
    /// Block root mismatch, caller should retry with different blocks.
    MismatchedBlockRoot {
        block_root: Hash256,
        expected_block_root: Hash256,
    },
    /// Bad signature, caller should retry with different blocks.
    SignatureSet(SignatureSetError),
    /// Bad signature, caller should retry with different blocks.
    InvalidSignature,
    /// Transitory error, caller should retry with the same blocks.
    ValidatorPubkeyCacheTimeout,
    /// Logic error: should never occur.
    IndexOutOfBounds,
    /// Internal store error
    StoreError(StoreError),
}

impl From<StoreError> for HistoricalBlockError {
    fn from(e: StoreError) -> Self {
        Self::StoreError(e)
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
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
                self.log,
                "Ignoring some historic blocks";
                "oldest_block_slot" => anchor_info.oldest_block_slot,
                "total_blocks" => total_blocks,
                "ignored" => total_blocks.saturating_sub(blocks_to_import.len()),
            );
        }

        if blocks_to_import.is_empty() {
            return Ok(0);
        }

        // Blobs are stored per block, and data columns are each stored individually
        let n_blob_ops_per_block = if self.spec.is_peer_das_scheduled() {
            // TODO(das): `available_block includes all sampled columns, but we only need to store
            // custody columns. To be clarified in spec PR.
            self.data_availability_checker.get_sampling_column_count()
        } else {
            1
        };

        let blob_batch_size = blocks_to_import
            .iter()
            .filter(|available_block| available_block.blobs().is_some())
            .count()
            .saturating_mul(n_blob_ops_per_block);

        let mut expected_block_root = anchor_info.oldest_block_parent;
        let mut prev_block_slot = anchor_info.oldest_block_slot;
        let mut new_oldest_blob_slot = blob_info.oldest_blob_slot;
        let mut new_oldest_data_column_slot = data_column_info.oldest_data_column_slot;

        let mut blob_batch = Vec::with_capacity(blob_batch_size);
        let mut cold_batch = Vec::with_capacity(blocks_to_import.len());
        let mut hot_batch = Vec::with_capacity(blocks_to_import.len());
        let mut signed_blocks = Vec::with_capacity(blocks_to_import.len());

        for available_block in blocks_to_import.into_iter().rev() {
            let (block_root, block, maybe_blobs, maybe_data_columns) =
                available_block.deconstruct();

            if block_root != expected_block_root {
                return Err(HistoricalBlockError::MismatchedBlockRoot {
                    block_root,
                    expected_block_root,
                });
            }

            let blinded_block = block.clone_as_blinded();
            // Store block in the hot database without payload.
            self.store
                .blinded_block_as_kv_store_ops(&block_root, &blinded_block, &mut hot_batch);
            // Store the blobs too
            if let Some(blobs) = maybe_blobs {
                new_oldest_blob_slot = Some(block.slot());
                self.store
                    .blobs_as_kv_store_ops(&block_root, blobs, &mut blob_batch);
            }
            // Store the data columns too
            if let Some(data_columns) = maybe_data_columns {
                new_oldest_data_column_slot = Some(block.slot());
                self.store
                    .data_columns_as_kv_store_ops(&block_root, data_columns, &mut blob_batch);
            }

            // Store block roots, including at all skip slots in the freezer DB.
            for slot in (block.slot().as_u64()..prev_block_slot.as_u64()).rev() {
                cold_batch.push(KeyValueStoreOp::PutKeyValue(
                    get_key_for_col(DBColumn::BeaconBlockRoots.into(), &slot.to_be_bytes()),
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
                        get_key_for_col(DBColumn::BeaconBlockRoots.into(), &slot.to_be_bytes()),
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
            .map_err(HistoricalBlockError::SignatureSet)
            .map(ParallelSignatureSets::from)?;
        drop(pubkey_cache);
        drop(setup_timer);

        let verify_timer = metrics::start_timer(&metrics::BACKFILL_SIGNATURE_VERIFY_TIMES);
        if !signature_set.verify() {
            return Err(HistoricalBlockError::InvalidSignature);
        }
        drop(verify_timer);
        drop(sig_timer);

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
