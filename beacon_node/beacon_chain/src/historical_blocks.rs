use crate::block_verification_types::RangeSyncBlock;
use crate::data_availability_checker::AvailableBlockData;
use crate::payload_envelope_verification::verify_envelope_payload_hash;
use crate::{BeaconChain, BeaconChainTypes, WhenSlotSkipped, metrics};
use fixed_bytes::FixedBytesExtended;
use itertools::Itertools;
use state_processing::{
    per_block_processing::ParallelSignatureSets,
    signature_sets::{Error as SignatureSetError, block_proposal_signature_set_from_parts},
};
use std::borrow::Cow;
use std::iter;
use std::time::Duration;
use store::metadata::DataColumnInfo;
use store::{AnchorInfo, BlobInfo, DBColumn, Error as StoreError, KeyValueStore, KeyValueStoreOp};
use strum::IntoStaticStr;
use tracing::{debug, debug_span, instrument};
use types::{EthSpec, Hash256, Slot, consts::gloas::BUILDER_INDEX_SELF_BUILD};

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
    /// Logic error: should never occur.
    MissingOldestBlockRoot { slot: Slot },
    /// A Gloas block with a revealed payload is missing its envelope. Caller should
    /// retry/penalize.
    MissingEnvelope { block_root: Hash256 },
    /// A Gloas payload envelope failed verification against its block's committed bid
    /// (e.g. the recomputed execution block hash doesn't match). Caller should retry/penalize.
    InvalidEnvelope { block_root: Hash256, reason: String },
    /// The proposer pubkey of a root-chained block is missing from the pubkey cache.
    /// Logic error: internal inconsistency, do not penalize peers.
    MissingProposerPubkey {
        block_root: Hash256,
        proposer_index: u64,
    },
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
    /// `oldest_block_slot` to be provided. They will be re-imported to fill the columns of the
    /// checkpoint sync block.
    ///
    /// This function should not be called concurrently with any other function that mutates
    /// the anchor info (including this function itself). If a concurrent mutation occurs that
    /// would violate consistency then an `AnchorInfoConcurrentMutation` error will be returned.
    ///
    /// Return the number of blocks successfully imported.
    #[instrument(skip_all)]
    pub fn import_historical_block_batch(
        &self,
        mut blocks: Vec<RangeSyncBlock<T::EthSpec>>,
    ) -> Result<usize, HistoricalBlockError> {
        let anchor_info = self.store.get_anchor_info();
        let blob_info = self.store.get_blob_info();
        let data_column_info = self.store.get_data_column_info();

        // Take all blocks with slots less than or equal to the oldest block slot.
        //
        // This allows for reimport of the blobs/columns for the finalized block after checkpoint
        // sync.
        let num_relevant = blocks
            .partition_point(|block| block.as_block().slot() <= anchor_info.oldest_block_slot);

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
        let mut last_block_root = expected_block_root;
        let mut prev_block_slot = anchor_info.oldest_block_slot;
        let mut new_oldest_blob_slot = blob_info.oldest_blob_slot;
        let mut new_oldest_data_column_slot = data_column_info.oldest_data_column_slot;

        // A Gloas block's payload was revealed ("full") if its child's bid `parent_block_hash`
        // matches its own bid `block_hash`, see `process_parent_execution_payload` in the spec.
        // We iterate backwards, so track the child's bid hash as we go. Blocks with withheld
        // payloads never have an envelope, so we don't require one for them.
        //
        // Start from the anchor block, the child of the newest block in the batch. If the newest
        // block is the anchor itself being re-imported it has no child to derive reveal-status
        // from; seed `None` (indeterminate) so its envelope and columns are stored rather than
        // dropped by a self-comparison that is always false.
        let mut child_bid_parent_hash = blocks_to_import
            .last()
            .filter(|block| matches!(block, RangeSyncBlock::Gloas { .. }))
            .and_then(|newest_block| {
                let anchor_child_root = self
                    .block_root_at_slot(anchor_info.oldest_block_slot, WhenSlotSkipped::None)
                    .ok()
                    .flatten()?;
                if anchor_child_root == newest_block.block_root() {
                    return None;
                }
                let child_block = self.get_blinded_block(&anchor_child_root).ok().flatten()?;
                child_block
                    .message()
                    .body()
                    .signed_execution_payload_bid()
                    .ok()
                    .map(|bid| bid.message.parent_block_hash)
            });

        let mut blob_batch = Vec::<KeyValueStoreOp>::new();
        let mut cold_batch = Vec::with_capacity(blocks_to_import.len());
        let mut hot_batch = Vec::with_capacity(blocks_to_import.len());
        let mut signed_blocks = Vec::with_capacity(blocks_to_import.len());
        // Self-built envelopes whose signatures are verified in the batch signature section
        // below, using the proposer pubkey from the (batch-verified) block.
        let mut envelopes_to_verify = Vec::new();

        for range_sync_block in blocks_to_import.into_iter().rev() {
            let (block_root, block, block_data, envelope) = match range_sync_block {
                RangeSyncBlock::Base(available_block) => {
                    let (block_root, block, block_data) = available_block.deconstruct();
                    (block_root, block, block_data, None)
                }
                RangeSyncBlock::Gloas { block, envelope } => (
                    block.canonical_root(),
                    block,
                    AvailableBlockData::NoData,
                    envelope,
                ),
            };

            if block.slot() == anchor_info.oldest_block_slot {
                // When reimporting, verify that this is actually the same block (same block root).
                let oldest_block_root = self
                    .block_root_at_slot(block.slot(), WhenSlotSkipped::None)
                    .ok()
                    .flatten()
                    .ok_or(HistoricalBlockError::MissingOldestBlockRoot { slot: block.slot() })?;
                if block_root != oldest_block_root {
                    return Err(HistoricalBlockError::MismatchedBlockRoot {
                        block_root,
                        expected_block_root: oldest_block_root,
                    });
                }

                debug!(
                    ?block_root,
                    slot = %block.slot(),
                    "Re-importing historic block"
                );
                last_block_root = block_root;
            } else if block_root != expected_block_root {
                return Err(HistoricalBlockError::MismatchedBlockRoot {
                    block_root,
                    expected_block_root,
                });
            }

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
                AvailableBlockData::NoData => (),
                AvailableBlockData::Blobs(_) => new_oldest_blob_slot = Some(block.slot()),
                AvailableBlockData::DataColumns(_) => {
                    new_oldest_data_column_slot = Some(block.slot())
                }
            }

            // Store the blobs or data columns too
            if let Some(op) =
                self.get_blobs_or_columns_store_op(block_root, block.slot(), block_data)
            {
                blob_batch.extend(self.store.convert_to_kv_batch(vec![op])?);
            }

            // Whether this Gloas block's payload was revealed, per the child's bid (see the
            // comment on `child_bid_parent_hash` above). Tri-state on purpose:
            // - `Some(true)`: the child's bid proves the payload was revealed.
            // - `Some(false)`: the child's bid proves the payload was withheld.
            // - `None`: indeterminate — pre-Gloas block (no bid, no envelope expected) or the
            //   child's bid is unknown (e.g. the anchor-child lookup failed). In this case we
            //   neither require nor drop an envelope: dropping on indeterminate data would
            //   silently lose a legitimate envelope and leave a permanent serving gap.
            let payload_revealed: Option<bool> = block
                .message()
                .body()
                .signed_execution_payload_bid()
                .ok()
                .map(|bid| bid.message.block_hash)
                .and_then(|bid_hash| {
                    child_bid_parent_hash.map(|child_parent_hash| bid_hash == child_parent_hash)
                });

            // Persist the Gloas payload envelope and its data columns, which are carried by the
            // envelope rather than `block_data`.
            match envelope {
                // A withheld payload has no canonical envelope; do not persist whatever the
                // peer sent for it.
                Some(_) if payload_revealed == Some(false) => {
                    debug!(
                        ?block_root,
                        slot = %block.slot(),
                        "Dropping backfilled envelope for withheld payload"
                    );
                }
                Some(envelope) => {
                    // Recompute the payload's execution block hash against the bid committed in
                    // the (root-chained) block: the block root has been linked to the anchor at
                    // the top of this loop, so the bid is canonical even though proposer
                    // signatures are only batch-verified further below. Batches are only
                    // accepted from the network here, so a mismatch is attributable to the
                    // sending peer.
                    if self.config.verify_envelope_payload_hash_in_backfill {
                        verify_envelope_payload_hash(envelope.envelope(), &block).map_err(|e| {
                            HistoricalBlockError::InvalidEnvelope {
                                block_root,
                                reason: format!("{e:?}"),
                            }
                        })?;
                    }
                    if envelope.envelope().message.builder_index == BUILDER_INDEX_SELF_BUILD {
                        envelopes_to_verify.push((
                            block_root,
                            envelope.envelope().clone(),
                            block.message().proposer_index(),
                            block.slot().epoch(T::EthSpec::slots_per_epoch()),
                        ));
                    }
                    let (signed_envelope, columns) = envelope.deconstruct();
                    if !columns.is_empty() {
                        new_oldest_data_column_slot = Some(block.slot());
                        if let Some(op) = self.get_blobs_or_columns_store_op(
                            block_root,
                            block.slot(),
                            AvailableBlockData::DataColumns(columns),
                        ) {
                            blob_batch.extend(self.store.convert_to_kv_batch(vec![op])?);
                        }
                    }
                    self.store.payload_envelope_as_kv_store_ops(
                        &block_root,
                        &signed_envelope,
                        &mut hot_batch,
                    );
                }
                None => {
                    // Envelopes must be stored for every revealed payload (even with no blobs)
                    // so we can serve them over RPC and use them for state reconstruction.
                    // Withheld payloads never have one, and we don't require one when
                    // revealed-ness is indeterminate.
                    if payload_revealed == Some(true) {
                        return Err(HistoricalBlockError::MissingEnvelope { block_root });
                    }
                }
            }

            // Store block roots, including at all skip slots in the freezer DB.
            for slot in (block.slot().as_u64()..prev_block_slot.as_u64()).rev() {
                debug!(%slot, ?block_root, "Storing frozen block to root mapping");
                cold_batch.push(KeyValueStoreOp::PutKeyValue(
                    DBColumn::BeaconBlockRoots,
                    slot.to_be_bytes().to_vec(),
                    block_root.as_slice().to_vec(),
                ));
            }

            prev_block_slot = block.slot();
            expected_block_root = block.message().parent_root();
            // This block is the child of the next (older) block in the iteration.
            child_bid_parent_hash = block
                .message()
                .body()
                .signed_execution_payload_bid()
                .ok()
                .map(|bid| bid.message.parent_block_hash);
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

        // Verify self-built envelope signatures with the proposer's pubkey. The proposer index
        // is trusted because the containing block's proposer signature is verified below.
        // External-builder envelopes cannot be verified historically (the builder registry is
        // not reconstructible without historical states); their contents are still bound to the
        // bid via the block hash recompute above.
        for (envelope_block_root, signed_envelope, proposer_index, epoch) in &envelopes_to_verify {
            let pubkey = pubkey_cache.get(*proposer_index as usize).ok_or(
                HistoricalBlockError::MissingProposerPubkey {
                    block_root: *envelope_block_root,
                    proposer_index: *proposer_index,
                },
            )?;
            let fork = self.spec.fork_at_epoch(*epoch);
            if !signed_envelope.verify_signature(
                pubkey,
                &fork,
                self.genesis_validators_root,
                &self.spec,
            ) {
                return Err(HistoricalBlockError::InvalidEnvelope {
                    block_root: *envelope_block_root,
                    reason: "invalid self-build envelope signature".to_string(),
                });
            }
        }
        let block_roots = signed_blocks
            .get(1..)
            .ok_or(HistoricalBlockError::IndexOutOfBounds)?
            .iter()
            .map(|block| block.parent_root())
            .chain(iter::once(last_block_root));
        let signature_set = signed_blocks
            .iter()
            .zip_eq(block_roots)
            .filter(|&(_block, block_root)| block_root != self.genesis_block_root)
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
        {
            let _span = debug_span!("backfill_write_blobs_db").entered();
            self.store.blobs_db.do_atomically(blob_batch)?;
        }
        {
            let _span = debug_span!("backfill_write_hot_db").entered();
            self.store.hot_db.do_atomically(hot_batch)?;
        }
        {
            let _span = debug_span!("backfill_write_cold_db").entered();
            self.store.cold_db.do_atomically(cold_batch)?;
        }

        let mut anchor_and_blob_batch = Vec::with_capacity(3);

        // Update the blob info.
        if new_oldest_blob_slot != blob_info.oldest_blob_slot
            && let Some(oldest_blob_slot) = new_oldest_blob_slot
        {
            let new_blob_info = BlobInfo {
                oldest_blob_slot: Some(oldest_blob_slot),
                ..blob_info.clone()
            };
            anchor_and_blob_batch.push(
                self.store
                    .compare_and_set_blob_info(blob_info, new_blob_info)?,
            );
        }

        // Update the data column info.
        if new_oldest_data_column_slot != data_column_info.oldest_data_column_slot
            && let Some(oldest_data_column_slot) = new_oldest_data_column_slot
        {
            let new_data_column_info = DataColumnInfo {
                oldest_data_column_slot: Some(oldest_data_column_slot),
            };
            anchor_and_blob_batch.push(
                self.store
                    .compare_and_set_data_column_info(data_column_info, new_data_column_info)?,
            );
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
        if backfill_complete && self.genesis_backfill_slot == Slot::new(0) && self.config.archive {
            self.store_migrator.process_reconstruction();
        }

        Ok(num_relevant)
    }
}
