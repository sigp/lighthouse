//! Import ERA files into a Lighthouse database.
//!
//! [`EraFileDir`] reads a directory of ERA files and imports them sequentially into the cold DB.
//! Each ERA file is verified against `historical_roots` / `historical_summaries` from the
//! highest-numbered ERA state, ensuring block and state integrity without trusting the files.
//!
//! The trust chain works as follows:
//! 1. The reference (highest-numbered) ERA state is verified against an [`EraImportTrust`] anchor
//!    — either a user-provided state root or the network's `genesis_validators_root`.
//! 2. Each ERA state's `block_roots` / `state_roots` are checked against `historical_roots`
//!    (pre-Capella) or `historical_summaries` (post-Capella) from the reference state.
//! 3. Each block's root is checked against the ERA boundary state's `block_roots` vector.
//!
//! Block signatures are NOT verified — ERA files are trusted at that level.
//!
//! # Usage
//!
//! ```ignore
//! let trust = EraImportTrust::TrustedStateRoot(758, known_root);
//! let era_dir = EraFileDir::new::<E>(&path, genesis_validators_root, trust, &spec)?;
//! store.put_cold_state(&genesis_state_root, &genesis_state)?;
//! era_dir.import_all(&store, &spec)?;
//! ```

use crate::BeaconForkChoiceStore;
use crate::beacon_chain::FORK_CHOICE_DB_KEY;
use crate::beacon_fork_choice_store::PersistedForkChoiceStore;
use crate::persisted_fork_choice::PersistedForkChoice;
use bls::FixedBytesExtended;
use fork_choice::ForkChoice;
use rayon::prelude::*;
use reth_era::common::file_ops::StreamReader;
use reth_era::era::file::EraReader;
use reth_era::era::types::consensus::{CompressedBeaconState, CompressedSignedBeaconBlock};

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use store::{DBColumn, HotColdDB, ItemStore, KeyValueStoreOp};
use tracing::{debug, debug_span, info, instrument, warn};
use tree_hash::TreeHash;
use types::{
    BeaconState, ChainSpec, Checkpoint, EthSpec, Hash256, HistoricalBatch, HistoricalSummary,
    SignedBeaconBlock, Slot,
};

fn decode_block<E: EthSpec>(
    compressed: CompressedSignedBeaconBlock,
    spec: &ChainSpec,
) -> Result<SignedBeaconBlock<E>, String> {
    let bytes = compressed
        .decompress()
        .map_err(|error| format!("failed to decompress block: {error:?}"))?;
    SignedBeaconBlock::from_ssz_bytes(&bytes, spec)
        .map_err(|error| format!("failed to decode block: {error:?}"))
}

fn decode_state<E: EthSpec>(
    compressed: CompressedBeaconState,
    spec: &ChainSpec,
) -> Result<BeaconState<E>, String> {
    let bytes = compressed
        .decompress()
        .map_err(|error| format!("failed to decompress state: {error:?}"))?;
    BeaconState::from_ssz_bytes(&bytes, spec)
        .map_err(|error| format!("failed to decode state: {error:?}"))
}

/// How to select and verify the reference ERA state.
///
/// The reference state provides `historical_roots` / `historical_summaries` used to verify
/// every other ERA file. This enum controls which ERA is the reference and how it's verified.
pub enum EraImportTrust {
    /// Use the ERA at the given number as the reference state. Its `canonical_root()` is
    /// verified against the provided root. Only ERAs 0..=era_number are imported.
    TrustedStateRoot(u64, Hash256),
    /// Use the highest-numbered ERA in the directory as the reference state. No external
    /// root verification — only check internal consistency and `genesis_validators_root`.
    Untrusted,
}

/// A directory of ERA files ready for import into a Lighthouse cold DB.
///
/// On construction, reads the highest-numbered ERA file's state to extract
/// `historical_roots` and `historical_summaries`, which are used to verify every subsequent
/// ERA file during import. Validates that:
/// - All expected ERA files (0 through max) are present in the directory
/// - `genesis_validators_root` matches the provided value (correct network)
/// - If [`EraImportTrust::TrustedStateRoot`] is provided, the reference state root matches
///
/// Use [`EraFileDir::import_all`] to import all ERA files into a store,
/// or [`EraFileDir::import_era_file`] for individual ERA import.
#[derive(Debug)]
pub struct EraFileDir {
    dir: PathBuf,
    network_name: String,
    genesis_validators_root: Hash256,
    historical_roots: Vec<Hash256>,
    historical_summaries: Vec<HistoricalSummary>,
    max_era: u64,
}

impl EraFileDir {
    /// Open an ERA file directory and verify trust.
    ///
    /// Selects a reference ERA state based on `trust`:
    /// - [`EraImportTrust::TrustedStateRoot`]: uses the specified ERA, verifies its root,
    ///   imports only ERAs 0..=era_number.
    /// - [`EraImportTrust::Untrusted`]: uses the highest-numbered ERA, imports all.
    ///
    /// The reference state's `historical_roots` / `historical_summaries` are extracted to
    /// verify all other ERA files during import.
    pub fn new<E: EthSpec>(
        era_files_dir: &Path,
        genesis_validators_root: Hash256,
        trust: EraImportTrust,
        spec: &ChainSpec,
    ) -> Result<Self, String> {
        let mut era_files = list_era_files(era_files_dir)?;
        era_files.sort_by_key(|(era_number, _)| *era_number);

        let network_name = spec
            .config_name
            .clone()
            .unwrap_or_else(|| "unknown".to_string());

        let (max_era, reference_state) = match trust {
            EraImportTrust::TrustedStateRoot(era_number, expected_root) => {
                let (_, path) = era_files
                    .iter()
                    .find(|(n, _)| *n == era_number)
                    .ok_or_else(|| format!("trusted era {era_number} not found in directory"))?;
                let mut state = read_era_state::<E>(path, &network_name, spec)?;
                let actual_root = state
                    .canonical_root()
                    .map_err(|e| format!("failed to compute reference state root: {e:?}"))?;
                if actual_root != expected_root {
                    return Err(format!(
                        "trusted state root mismatch for era {era_number}: \
                         expected {expected_root:?}, got {actual_root:?}"
                    ));
                }
                (era_number, state)
            }
            EraImportTrust::Untrusted => {
                let (n, path) = era_files
                    .last()
                    .ok_or_else(|| "era files directory is empty".to_string())?;
                let state = read_era_state::<E>(path, &network_name, spec)?;
                (*n, state)
            }
        };

        if reference_state.genesis_validators_root() != genesis_validators_root {
            return Err(format!(
                "ERA files genesis_validators_root ({:?}) does not match expected ({:?}). \
                 Are the ERA files from the correct network?",
                reference_state.genesis_validators_root(),
                genesis_validators_root,
            ));
        }

        // historical_roots was frozen in capella, and continued as historical_summaries
        let historical_roots = reference_state.historical_roots().to_vec();
        // Pre-Capella states don't have historical_summaries property
        let historical_summaries = match reference_state.historical_summaries() {
            Ok(list) => list.to_vec(),
            Err(_) => vec![],
        };

        let dir = era_files_dir.to_path_buf();
        let era_dir = Self {
            dir,
            network_name,
            genesis_validators_root,
            historical_roots,
            historical_summaries,
            max_era,
        };

        // Verify that every expected era file name exists in the directory.
        for era_number in 0..=era_dir.max_era {
            let expected = era_dir.expected_path(era_number);
            if !expected.exists() {
                return Err(format!("missing era file: {expected:?}"));
            }
        }

        Ok(era_dir)
    }

    pub fn max_era(&self) -> u64 {
        self.max_era
    }

    pub fn genesis_validators_root(&self) -> Hash256 {
        self.genesis_validators_root
    }

    /// Import ERA files 1 through `max_era` into the store, then advance the chain state.
    ///
    /// The caller must have initialized the store from genesis first via [`init_genesis_store`].
    /// After importing all ERA files, the split, fork choice, and anchor are advanced to the
    /// latest ERA boundary slot so the store is ready for `resume_from_db`.
    pub fn import_all<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
        &self,
        store: &Arc<HotColdDB<E, Hot, Cold>>,
        spec: &ChainSpec,
    ) -> Result<(), String> {
        let start = std::time::Instant::now();
        let max_era = self.max_era;
        let slots_per_historical_root = E::slots_per_historical_root() as u64;

        // Resume from last successfully imported ERA
        let imported_pointer = store
            .get_era_import_pointer()
            .map_err(|e| format!("ERA import pointer read failed: {e:?}"))?
            .unwrap_or(0);

        info!(
            max_era,
            resume_from = imported_pointer + 1,
            "Importing ERA files"
        );

        let mut last_log = std::time::Instant::now();
        for era_number in imported_pointer + 1..=max_era {
            self.import_era_file(store, era_number, spec)?;

            // Persist progress pointer after each ERA
            store
                .set_era_import_pointer(era_number)
                .map_err(|e| format!("ERA import pointer write failed: {e:?}"))?;

            // Rate-limited progress logging (every 5 seconds)
            let now = std::time::Instant::now();
            if now.duration_since(last_log) >= std::time::Duration::from_secs(5) {
                last_log = now;
                let done_slots = era_number * slots_per_historical_root;
                let total_slots = max_era * slots_per_historical_root;
                info!(
                    completed_era_files = era_number,
                    total_era_files = max_era,
                    completed_slots = done_slots,
                    total_slots,
                    "Importing ERA files"
                );
            }
        }

        info!(
            max_era,
            "ERA file import complete, starting state reconstruction"
        );

        // Parallel state reconstruction
        self.reconstruct_states_parallel::<E, Hot, Cold>(
            store,
            max_era,
            slots_per_historical_root,
        )?;

        // Advance the store metadata from genesis to the latest ERA boundary.
        self.advance_store_to_era::<E, Hot, Cold>(store, spec)?;

        info!(
            max_era,
            elapsed = ?start.elapsed(),
            "ERA file import and reconstruction complete"
        );

        Ok(())
    }

    /// Reconstruct all intermediate states in parallel using rayon.
    ///
    /// Each ERA's states are reconstructed independently by replaying blocks from the
    /// ERA boundary state. Progress is tracked per-ERA so reconstruction can resume
    /// after a crash.
    fn reconstruct_states_parallel<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
        &self,
        store: &Arc<HotColdDB<E, Hot, Cold>>,
        max_era: u64,
        slots_per_historical_root: u64,
    ) -> Result<(), String> {
        use std::sync::atomic::{AtomicU64, Ordering};

        let total_era_files = max_era;
        let completed = Arc::new(AtomicU64::new(0));
        let progress = Arc::new(parking_lot::Mutex::new(std::time::Instant::now()));

        (1..=max_era).into_par_iter().try_for_each(|era_number| {
            let already_done = store
                .era_reconstruction_done(era_number)
                .map_err(|e| format!("ERA reconstruction marker read failed: {e:?}"))?;

            if !already_done {
                let start_slot = Slot::new((era_number - 1) * slots_per_historical_root);
                let end_slot = Slot::new(era_number * slots_per_historical_root);
                store
                    .reconstruct_historic_states_on_range(start_slot, end_slot, |_| Ok(()))
                    .map_err(|e| {
                        format!("ERA reconstruction failed for era {era_number}: {e:?}")
                    })?;

                store
                    .set_era_reconstruction_done(era_number)
                    .map_err(|e| format!("ERA reconstruction marker write failed: {e:?}"))?;
            }

            let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
            let now = std::time::Instant::now();
            let mut last_log = progress.lock();
            if now.duration_since(*last_log) >= std::time::Duration::from_secs(5) {
                *last_log = now;
                info!(
                    completed_era_files = done,
                    total_era_files, "Reconstructing states from ERA files"
                );
            }

            Ok::<(), String>(())
        })?;

        Ok(())
    }

    /// Advance split, fork choice, and anchor from genesis to the latest ERA boundary slot.
    fn advance_store_to_era<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
        &self,
        store: &Arc<HotColdDB<E, Hot, Cold>>,
        spec: &ChainSpec,
    ) -> Result<(), String> {
        let slots_per_hr = E::slots_per_historical_root() as u64;
        let head_slot = Slot::new(self.max_era * slots_per_hr);

        // Load the latest ERA state (already in cold DB from import)
        let mut head_state = store
            .load_cold_state_by_slot(head_slot)
            .map_err(|e| format!("failed to load head state at slot {head_slot}: {e:?}"))?;

        let head_state_root = head_state
            .canonical_root()
            .map_err(|e| format!("failed to compute head state root: {e:?}"))?;

        // Find the latest block root from the state's block_roots
        let last_block_slot = (0..slots_per_hr)
            .rev()
            .map(|i| Slot::new(head_slot.as_u64().saturating_sub(slots_per_hr) + i))
            .find(|slot| {
                head_state
                    .get_block_root(*slot)
                    .ok()
                    .map(|root| {
                        // Non-skipped slot: root differs from previous slot's root
                        slot.as_u64() == 0
                            || head_state
                                .get_block_root(Slot::new(slot.as_u64() - 1))
                                .ok()
                                .is_none_or(|prev| prev != root)
                    })
                    .unwrap_or(false)
            })
            .ok_or("no block found in last ERA")?;
        let head_block_root = *head_state
            .get_block_root(last_block_slot)
            .map_err(|e| format!("failed to read head block root: {e:?}"))?;

        // Update anchor to reflect imported and reconstructed ERA data:
        // - anchor_slot = head_slot so put_state uses Snapshot strategy
        // - state_lower_limit = 0, state_upper_limit = 0: all historic states reconstructed
        // - oldest_block_slot = 0: all blocks available
        {
            let old_anchor = store.get_anchor_info();
            let mut new_anchor = old_anchor.clone();
            new_anchor.anchor_slot = head_slot;
            new_anchor.state_lower_limit = Slot::new(0);
            new_anchor.state_upper_limit = Slot::new(0);
            new_anchor.oldest_block_slot = Slot::new(0);
            store
                .compare_and_set_anchor_info_with_write(old_anchor, new_anchor)
                .map_err(|e| format!("failed to update anchor: {e:?}"))?;
        }

        // Set split at the ERA boundary
        store.set_split(head_slot, head_state_root, head_block_root);

        // Store the head state in hot DB (needed by get_advanced_hot_state on startup).
        store
            .put_state(&head_state_root, &head_state)
            .map_err(|e| format!("failed to store head state in hot DB: {e:?}"))?;

        // Re-create fork choice with the head as anchor.
        //
        // We cannot use `get_forkchoice_store` here because the ERA boundary state's
        // `latest_block_header` may reference a block at the boundary slot that belongs to the
        // NEXT ERA and is not stored. Instead, construct the fork choice store directly using
        // `from_persisted` with the correct head block root and state root.
        let head_block = store
            .get_full_block(&head_block_root)
            .map_err(|e| format!("failed to load head block at slot {last_block_slot}: {e:?}"))?
            .ok_or_else(|| {
                format!("head block {head_block_root:?} not found at slot {last_block_slot}")
            })?;

        let anchor_epoch = head_state.current_epoch();
        let anchor_checkpoint = Checkpoint {
            epoch: anchor_epoch,
            root: head_block_root,
        };
        let persisted_fc_store = PersistedForkChoiceStore {
            time: head_slot,
            finalized_checkpoint: anchor_checkpoint,
            justified_checkpoint: anchor_checkpoint,
            justified_state_root: head_state_root,
            unrealized_justified_checkpoint: anchor_checkpoint,
            unrealized_justified_state_root: head_state_root,
            unrealized_finalized_checkpoint: anchor_checkpoint,
            proposer_boost_root: Hash256::zero(),
            equivocating_indices: BTreeSet::new(),
        };
        let fc_store = BeaconForkChoiceStore::from_persisted(persisted_fc_store, store.clone())
            .map_err(|e| format!("failed to create fork choice store: {e:?}"))?;
        let fork_choice = ForkChoice::from_anchor(
            fc_store,
            head_block_root,
            &head_block,
            &head_state,
            Some(head_slot),
            spec,
        )
        .map_err(|e| format!("failed to create fork choice: {e:?}"))?;

        // Persist updated metadata
        let mut batch = vec![];
        batch.push(store.store_split_in_batch());
        let persisted_fork_choice = PersistedForkChoice {
            fork_choice: fork_choice.to_persisted(),
            fork_choice_store: fork_choice.fc_store().to_persisted(),
        };
        batch.push(
            persisted_fork_choice
                .as_kv_store_op(FORK_CHOICE_DB_KEY, store.get_config())
                .map_err(|e| format!("failed to persist fork choice: {e:?}"))?,
        );
        store
            .hot_db
            .do_atomically(batch)
            .map_err(|e| format!("failed to write advanced metadata: {e:?}"))?;

        info!(
            head_slot = %head_slot,
            head_block_root = ?head_block_root,
            "Advanced store to latest ERA boundary"
        );

        Ok(())
    }

    #[instrument(level = "debug", skip_all, fields(era_number = %era_number))]
    pub fn import_era_file<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
        &self,
        store: &HotColdDB<E, Hot, Cold>,
        era_number: u64,
        spec: &ChainSpec,
    ) -> Result<(), String> {
        let path = self.expected_path(era_number);
        debug!(?path, era_number, "Importing era file");
        let file = File::open(path).map_err(|error| format!("failed to open era file: {error}"))?;
        let era_file = {
            let _ = debug_span!("era_import_read").entered();
            EraReader::new(file)
                .read_and_assemble(self.network_name.clone())
                .map_err(|error| format!("failed to parse era file: {error:?}"))?
        };

        // Consistency checks: ensure the era state matches the expected historical root and that
        // each block root matches the state block_roots for its slot.
        let mut state = {
            let _ = debug_span!("era_import_decode_state").entered();
            decode_state::<E>(era_file.group.era_state, spec)?
        };

        let expected_root = self
            .era_file_name_root(era_number)
            .ok_or_else(|| format!("missing historical root for era {era_number}"))?;
        let actual_root = era_root_from_state(&state, era_number)?;
        if expected_root != actual_root {
            return Err(format!(
                "era root mismatch for era {era_number}: expected {expected_root:?}, got {actual_root:?}"
            ));
        }

        let slots_per_historical_root = E::slots_per_historical_root() as u64;
        let end_slot = Slot::new(era_number * slots_per_historical_root);
        if state.slot() != end_slot {
            return Err(format!(
                "era state slot mismatch: expected {end_slot}, got {}",
                state.slot()
            ));
        }

        let historical_summaries_active_at_slot = match store.spec.capella_fork_epoch {
            // For mainnet case, Capella activates at 194048 epoch = 6209536 slot = 758 era number.
            // The last epoch processing before capella transition adds a last entry to historical
            // roots. So historical_roots.len() == 758 at the capella fork boundary. An ERA file
            // includes the state AFTER advanced (or applying) the block at the final slot, so the
            // state for ERA file 758 is of the Capella variant. However, historical summaries are
            // still empty.
            Some(epoch) => {
                epoch.start_slot(E::slots_per_epoch())
                    + Slot::new(E::slots_per_historical_root() as u64)
            }
            None => Slot::max_value(),
        };

        // Check that the block roots vector in this state match the historical summary in the last
        // state. Asserts that the blocks are exactly the expected ones given a trusted final state
        if era_number == 0 {
            // Skip checking genesis state era file for now
        } else if state.slot() >= historical_summaries_active_at_slot {
            // Post-capella state, check against historical summaries
            // ```py
            // historical_summary = HistoricalSummary(
            //     block_summary_root=hash_tree_root(state.block_roots),
            //     state_summary_root=hash_tree_root(state.state_roots),
            // )
            // state.historical_summaries.append(historical_summary)
            // ```
            let index = era_number.saturating_sub(1) as usize;
            // historical_summaries started to be appended after capella, so we need to offset
            let summary_index = index
                .checked_sub(self.historical_roots.len())
                .ok_or_else(|| format!(
                    "Not enough historical roots era number {era_number} index {index} historical_roots len {}",
                    self.historical_roots.len()
                ))?;
            let expected_root = self
                .historical_summaries
                .get(summary_index)
                .ok_or_else(|| format!("missing historical summary for era {era_number}"))?
                .block_summary_root();
            let actual_root = state.block_roots().tree_hash_root();
            if actual_root != expected_root {
                return Err(format!(
                    "block summary root post-capella mismatch for era {}: {:?} != {:?}",
                    era_number, expected_root, actual_root
                ));
            }
        } else {
            // Pre-capella state, check against historical roots
            // ```py
            // historical_batch = HistoricalBatch(block_roots=state.block_roots, state_roots=state.state_roots)
            // state.historical_roots.append(hash_tree_root(historical_batch))
            // ```
            let index = era_number.saturating_sub(1) as usize;
            let expected_root = *self
                .historical_roots
                .get(index)
                .ok_or_else(|| format!("missing historical root for era {era_number}"))?;
            let historical_batch = HistoricalBatch::<E> {
                block_roots: state.block_roots().clone(),
                state_roots: state.state_roots().clone(),
            };
            let actual_root = historical_batch.tree_hash_root();
            if actual_root != expected_root {
                return Err(format!(
                    "block summary root pre-capella mismatch for era {}: {:?} != {:?}",
                    era_number, expected_root, actual_root
                ));
            }
        }

        debug!(era_number, "Importing blocks from era file");
        // TODO(era): Block signatures are not verified here and are trusted.
        // decode and hash is split in two loops to track timings better. If we add spans for each
        // block it's too short and the data is not really useful.
        let decoded_blocks = {
            let _ = debug_span!("era_import_decode_blocks").entered();
            era_file
                .group
                .blocks
                .into_par_iter()
                .map(|compressed_block| decode_block::<E>(compressed_block, spec))
                .collect::<Result<Vec<_>, _>>()?
        };
        let blocks_with_roots = {
            let _ = debug_span!("era_import_hash_blocks").entered();
            decoded_blocks
                .into_par_iter()
                .map(|block| (block.canonical_root(), block))
                .collect::<Vec<_>>()
        };

        let mut block_ops = vec![];
        {
            let _ = debug_span!("era_import_db_ops_blocks").entered();
            for (block_root, block) in blocks_with_roots {
                let slot = block.slot();
                // Check consistency that this block is expected w.r.t. the state in the era file.
                // Since we check that the state block roots match the historical summary, we know that
                // this block root is the expected one.
                let expected_block_root = state
                    .get_block_root(slot)
                    .map_err(|error| format!("failed to read block root {slot}: {error:?}"))?;
                if *expected_block_root != block_root {
                    return Err(format!(
                        "block root mismatch at slot {slot}: expected {expected_block_root:?}, got {block_root:?}"
                    ));
                }
                store
                    .block_as_kv_store_ops(&block_root, block, &mut block_ops)
                    .map_err(|error| format!("failed to store block: {error:?}"))?;
            }
        }
        {
            let _ = debug_span!("era_import_write_blocks").entered();
            store
                .hot_db
                .do_atomically(block_ops)
                .map_err(|error| format!("failed to store blocks: {error:?}"))?;
        }

        // Populate the cold DB slot -> root indices from the state
        {
            let _ = debug_span!("era_import_write_block_index").entered();
            write_block_root_index_for_era(store, &state, era_number)?;
        }
        {
            let _ = debug_span!("era_import_write_state_root_index").entered();
            write_state_root_index_for_era(store, &state)?;
        }

        debug!(era_number, "Importing state from era file");
        {
            let _ = debug_span!("era_import_write_state").entered();
            let state_root = state
                .canonical_root()
                .map_err(|error| format!("failed to hash state: {error:?}"))?;
            // Use put_cold_state as the split is not updated and we need the state into the cold store.
            store
                .put_cold_state(&state_root, &state)
                .map_err(|error| format!("failed to store state: {error:?}"))?;
        }
        Ok(())
    }

    fn expected_path(&self, era_number: u64) -> PathBuf {
        let root = self
            .era_file_name_root(era_number)
            .unwrap_or_else(Hash256::zero);
        let short = root
            .as_slice()
            .iter()
            .take(4)
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let filename = format!("{}-{era_number:05}-{short}.era", self.network_name);
        self.dir.join(filename)
    }

    // era_file_name_root for file naming:
    // short-era-root is the first 4 bytes of the last historical root in the last state in the
    // era file, lower-case hex-encoded (8 characters), except the genesis era which instead
    // uses the genesis_validators_root field from the genesis state.
    // - The root is available as state.historical_roots[era - 1] except for genesis, which is
    //   state.genesis_validators_root
    // - Post-Capella, the root must be computed from
    //   `state.historical_summaries[era - state.historical_roots.len - 1]`
    fn era_file_name_root(&self, era_number: u64) -> Option<Hash256> {
        if era_number == 0 {
            return Some(self.genesis_validators_root);
        }
        let index = era_number.saturating_sub(1) as usize;
        if let Some(root) = self.historical_roots.get(index) {
            return Some(*root);
        }
        let summary_index = index.saturating_sub(self.historical_roots.len());
        self.historical_summaries
            .get(summary_index)
            .map(|summary| summary.tree_hash_root())
    }
}

fn read_era_state<E: EthSpec>(
    path: &Path,
    network_name: &str,
    spec: &ChainSpec,
) -> Result<BeaconState<E>, String> {
    let file = File::open(path).map_err(|error| format!("failed to open era file: {error}"))?;
    let era_file = EraReader::new(file)
        .read_and_assemble(network_name.to_string())
        .map_err(|error| format!("failed to parse era file: {error:?}"))?;
    decode_state::<E>(era_file.group.era_state, spec)
}

fn era_root_from_state<E: EthSpec>(
    state: &BeaconState<E>,
    era_number: u64,
) -> Result<Hash256, String> {
    if era_number == 0 {
        return Ok(state.genesis_validators_root());
    }
    let index = era_number
        .checked_sub(1)
        .ok_or_else(|| "invalid era number".to_string())? as usize;
    if let Some(root) = state.historical_roots().get(index) {
        return Ok(*root);
    }
    if let Ok(summaries) = state.historical_summaries() {
        let summary_index = index.saturating_sub(state.historical_roots().len());
        let summary = summaries
            .get(summary_index)
            .ok_or_else(|| "missing historical summary".to_string())?;
        return Ok(summary.tree_hash_root());
    }
    Err(format!("missing historical root for era {era_number}"))
}

fn write_block_root_index_for_era<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
    store: &HotColdDB<E, Hot, Cold>,
    state: &BeaconState<E>,
    era_number: u64,
) -> Result<(), String> {
    let end_slot = state.slot();
    let slots_per_historical_root = E::slots_per_historical_root() as u64;
    let expected_end_slot = Slot::new(era_number * slots_per_historical_root);
    if end_slot != expected_end_slot {
        return Err(format!(
            "era state slot mismatch: expected {expected_end_slot}, got {end_slot}"
        ));
    }

    let start_slot = end_slot.saturating_sub(slots_per_historical_root);

    let ops = (start_slot.as_u64()..end_slot.as_u64())
        .map(|slot_u64| {
            let slot = Slot::new(slot_u64);
            let block_root = state
                .get_block_root(slot)
                .map_err(|error| format!("failed to read block root {slot}: {error:?}"))?;
            // TODO(era): Should we write BeaconBlockRoots for missed slots?
            Ok(KeyValueStoreOp::PutKeyValue(
                DBColumn::BeaconBlockRoots,
                slot_u64.to_be_bytes().to_vec(),
                block_root.as_slice().to_vec(),
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;

    store
        .cold_db
        .do_atomically(ops)
        .map_err(|error| format!("failed to store block root index: {error:?}"))?;

    Ok(())
}

fn write_state_root_index_for_era<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
    store: &HotColdDB<E, Hot, Cold>,
    state: &BeaconState<E>,
) -> Result<(), String> {
    let end_slot = state.slot();
    let slots_per_historical_root = E::slots_per_historical_root() as u64;
    let start_slot = end_slot.saturating_sub(slots_per_historical_root);

    let mut ops = Vec::with_capacity((end_slot.as_u64() - start_slot.as_u64()) as usize * 2);
    for slot_u64 in start_slot.as_u64()..end_slot.as_u64() {
        let slot = Slot::new(slot_u64);
        let state_root = state
            .get_state_root(slot)
            .map_err(|error| format!("failed to read state root {slot}: {error:?}"))?;
        store
            .store_cold_state_summary(state_root, slot, &mut ops)
            .map_err(|error| format!("failed to build state root index op: {error:?}"))?;
    }

    store
        .cold_db
        .do_atomically(ops)
        .map_err(|error| format!("failed to store state root index: {error:?}"))?;

    Ok(())
}

/// Parse an ERA filename like `network-00042-aabbccdd.era` and return the era number.
fn parse_era_filename(name: &str) -> Option<u64> {
    let name = name.strip_suffix(".era")?;
    // Split: network-00042-aabbccdd → ["network", "00042", "aabbccdd"] (at least 3 parts)
    let mut parts = name.rsplitn(3, '-');
    let _hash = parts.next()?;
    let era_str = parts.next()?;
    let _network = parts.next()?;
    era_str.parse().ok()
}

fn list_era_files(dir: &Path) -> Result<Vec<(u64, PathBuf)>, String> {
    let entries = fs::read_dir(dir).map_err(|error| format!("failed to read era dir: {error}"))?;
    let mut era_files = Vec::new();

    for entry in entries {
        let entry = entry.map_err(|error| format!("failed to read era entry: {error}"))?;
        let path = entry.path();
        let file_name = path.file_name().and_then(|n| n.to_str());
        if let Some(era_number) = file_name.and_then(parse_era_filename) {
            era_files.push((era_number, path));
        }
    }

    if era_files.is_empty() {
        warn!(?dir, "Era files directory is empty");
    }

    Ok(era_files)
}

#[cfg(test)]
mod parse_tests {
    use super::parse_era_filename;

    #[test]
    fn valid_filenames() {
        assert_eq!(parse_era_filename("mainnet-00042-aabbccdd.era"), Some(42));
        assert_eq!(parse_era_filename("minimal-00000-12345678.era"), Some(0));
        assert_eq!(parse_era_filename("mainnet-01234-deadbeef.era"), Some(1234));
    }

    #[test]
    fn rejects_invalid() {
        assert_eq!(parse_era_filename("mainnet-00042-aabbccdd.txt"), None);
        assert_eq!(parse_era_filename("no-extension"), None);
        assert_eq!(parse_era_filename("mainnet-notanum-aabb.era"), None);
        assert_eq!(parse_era_filename("singlepart.era"), None);
        assert_eq!(parse_era_filename("two-parts.era"), None);
        assert_eq!(parse_era_filename(""), None);
    }
}
