use crate::{errors::BeaconChainError as Error, metrics, BeaconChain, BeaconChainTypes};
use itertools::Itertools;
use slog::debug;
use state_processing::{
    per_block_processing::ParallelSignatureSets,
    signature_sets::{block_proposal_signature_set_from_parts, Error as SignatureSetError},
};
use std::borrow::Cow;
use std::iter;
use std::time::Duration;
use store::{chunked_vector::BlockRoots, AnchorInfo, ChunkWriter, KeyValueStore};
use types::{Hash256, SignedBeaconBlock, Slot};

/// Use a longer timeout on the pubkey cache.
///
/// It's ok if historical sync is stalled due to writes from forwards block processing.
const PUBKEY_CACHE_LOCK_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub enum HistoricalBlockError {
    /// Block is not available (only returned when fetching historic blocks).
    BlockOutOfRange { slot: Slot, oldest_block_slot: Slot },
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
    /// No historical sync needed.
    NoAnchorInfo,
    /// Logic error: should never occur.
    IndexOutOfBounds,
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
        blocks: &[SignedBeaconBlock<T::EthSpec>],
    ) -> Result<usize, Error> {
        let anchor_info = self
            .store
            .get_anchor_info()
            .ok_or(HistoricalBlockError::NoAnchorInfo)?;

        // Take all blocks with slots less than the oldest block slot.
        let num_relevant =
            blocks.partition_point(|block| block.slot() < anchor_info.oldest_block_slot);
        let blocks_to_import = &blocks
            .get(..num_relevant)
            .ok_or(HistoricalBlockError::IndexOutOfBounds)?;

        if blocks_to_import.len() != blocks.len() {
            debug!(
                self.log,
                "Ignoring some historic blocks";
                "oldest_block_slot" => anchor_info.oldest_block_slot,
                "total_blocks" => blocks.len(),
                "ignored" => blocks.len().saturating_sub(blocks_to_import.len()),
            );
        }

        if blocks_to_import.is_empty() {
            return Ok(0);
        }

        let mut expected_block_root = anchor_info.oldest_block_parent;
        let mut prev_block_slot = anchor_info.oldest_block_slot;
        let mut chunk_writer =
            ChunkWriter::<BlockRoots, _, _>::new(&self.store.cold_db, prev_block_slot.as_usize())?;

        let mut cold_batch = Vec::with_capacity(blocks.len());
        let mut hot_batch = Vec::with_capacity(blocks.len());

        for block in blocks_to_import.iter().rev() {
            // Check chain integrity.
            let block_root = block.canonical_root();

            if block_root != expected_block_root {
                return Err(HistoricalBlockError::MismatchedBlockRoot {
                    block_root,
                    expected_block_root,
                }
                .into());
            }

            // Store block in the hot database.
            hot_batch.push(self.store.block_as_kv_store_op(&block_root, block));

            // Store block roots, including at all skip slots in the freezer DB.
            for slot in (block.slot().as_usize()..prev_block_slot.as_usize()).rev() {
                chunk_writer.set(slot, block_root, &mut cold_batch)?;
            }

            prev_block_slot = block.slot();
            expected_block_root = block.message().parent_root();

            // If we've reached genesis, add the genesis block root to the batch and set the
            // anchor slot to 0 to indicate completion.
            if expected_block_root == self.genesis_block_root {
                let genesis_slot = self.spec.genesis_slot;
                chunk_writer.set(
                    genesis_slot.as_usize(),
                    self.genesis_block_root,
                    &mut cold_batch,
                )?;
                prev_block_slot = genesis_slot;
                expected_block_root = Hash256::zero();
                break;
            }
        }
        chunk_writer.write(&mut cold_batch)?;

        // Verify signatures in one batch, holding the pubkey cache lock for the shortest duration
        // possible. For each block fetch the parent root from its successor. Slicing from index 1
        // is safe because we've already checked that `blocks_to_import` is non-empty.
        let sig_timer = metrics::start_timer(&metrics::BACKFILL_SIGNATURE_TOTAL_TIMES);
        let setup_timer = metrics::start_timer(&metrics::BACKFILL_SIGNATURE_SETUP_TIMES);
        let pubkey_cache = self
            .validator_pubkey_cache
            .try_read_for(PUBKEY_CACHE_LOCK_TIMEOUT)
            .ok_or(HistoricalBlockError::ValidatorPubkeyCacheTimeout)?;
        let block_roots = blocks_to_import
            .get(1..)
            .ok_or(HistoricalBlockError::IndexOutOfBounds)?
            .iter()
            .map(|block| block.parent_root())
            .chain(iter::once(anchor_info.oldest_block_parent));
        let signature_set = blocks_to_import
            .iter()
            .zip_eq(block_roots)
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
            return Err(HistoricalBlockError::InvalidSignature.into());
        }
        drop(verify_timer);
        drop(sig_timer);

        // Write the I/O batches to disk, writing the blocks themselves first, as it's better
        // for the hot DB to contain extra blocks than for the cold DB to point to blocks that
        // do not exist.
        self.store.hot_db.do_atomically(hot_batch)?;
        self.store.cold_db.do_atomically(cold_batch)?;

        // Update the anchor.
        let new_anchor = AnchorInfo {
            oldest_block_slot: prev_block_slot,
            oldest_block_parent: expected_block_root,
            ..anchor_info
        };
        let backfill_complete = new_anchor.block_backfill_complete();
        self.store
            .compare_and_set_anchor_info_with_write(Some(anchor_info), Some(new_anchor))?;

        // If backfill has completed and the chain is configured to reconstruct historic states,
        // send a message to the background migrator instructing it to begin reconstruction.
        if backfill_complete && self.config.reconstruct_historic_states {
            self.store_migrator.process_reconstruction();
        }

        Ok(blocks_to_import.len())
    }
}
