//! Export ERA files from a Lighthouse database.
//!
//! Reads blocks and states from the cold DB and writes them into the standardized ERA format.
//! ERA files are produced either during historical reconstruction (backfilling) or upon
//! finalization of new eras. Each file is named `{network}-{era_number}-{short_root}.era`.
//!
//! Files are written atomically (temp file + rename) so partial writes never appear as valid
//! ERA files. Existing files are skipped, making production idempotent.

use rand::random;
use reth_era::common::file_ops::{EraFileFormat, EraFileId, StreamWriter};
use reth_era::era::file::{EraFile, EraWriter};
use reth_era::era::types::consensus::{CompressedBeaconState, CompressedSignedBeaconBlock};
use reth_era::era::types::group::{EraGroup, EraId, SlotIndex};
use ssz::Encode;
use std::fs::{self, File, OpenOptions};
use std::path::Path;
use store::{HotColdDB, ItemStore};
use tracing::info;
use tree_hash::TreeHash;
use types::{BeaconState, EthSpec, Slot};

fn era_file_exists(dir: &Path, id: &EraId) -> bool {
    dir.join(id.to_file_name()).exists()
}

fn era_file_exists_for_number(dir: &Path, network_name: &str, era_number: u64) -> bool {
    let prefix = format!("{}-{:05}-", network_name, era_number);
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if name.starts_with(&prefix) && name.ends_with(".era") {
            return true;
        }
    }
    false
}

pub fn create_era_file<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
    db: &HotColdDB<E, Hot, Cold>,
    era_number: u64,
    output_dir: &Path,
) -> Result<(), String> {
    let network_name = db
        .spec
        .config_name
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    if era_file_exists_for_number(output_dir, &network_name, era_number) {
        return Ok(());
    }

    let end_slot = Slot::new(era_number * E::slots_per_historical_root() as u64);

    let mut state = db
        .load_cold_state_by_slot(end_slot)
        .map_err(|error| format!("failed to load era state: {error:?}"))?;

    if state.slot() != end_slot {
        return Err(format!(
            "era state slot mismatch: expected {}, got {}",
            end_slot,
            state.slot()
        ));
    }

    let group = build_era_group(db, &mut state, era_number)?;
    let file_id = era_file_id::<E>(&network_name, era_number, &mut state)?;
    let file = EraFile::new(group, file_id);

    fs::create_dir_all(output_dir)
        .map_err(|error| format!("failed to create era files dir: {error}"))?;

    if era_file_exists(output_dir, file.id()) {
        return Ok(());
    }

    write_era_file_atomic(output_dir, &file)?;

    info!(
        era_number,
        file = %file.id().to_file_name(),
        "Wrote era file"
    );

    Ok(())
}

pub(super) fn build_era_group<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
    db: &HotColdDB<E, Hot, Cold>,
    state: &mut BeaconState<E>,
    era_number: u64,
) -> Result<EraGroup, String> {
    // Era file 0 goes from slot 0 to 0, genesis state only
    let start_slot =
        Slot::new(era_number.saturating_sub(1) * E::slots_per_historical_root() as u64);
    let end_slot = Slot::new(era_number * E::slots_per_historical_root() as u64);

    let compressed_state = CompressedBeaconState::from_ssz(&state.as_ssz_bytes())
        .map_err(|error| format!("failed to compress state: {error:?}"))?;

    // Each entry has an 8-byte header; the version record is header-only.
    let mut offset: i64 = 8;
    let mut blocks: Vec<CompressedSignedBeaconBlock> = Vec::new();
    let mut block_data_starts: Vec<(Slot, i64)> = Vec::new();

    // The era file number 0 contains the genesis state and nothing else
    if era_number > 0 {
        for slot_u64 in start_slot.as_u64()..end_slot.as_u64() {
            let slot = Slot::new(slot_u64);
            let block_root = state
                .get_block_root(slot)
                .map_err(|error| format!("failed to read block root {slot}: {error:?}"))?;

            // Skip missed slots: if this slot's block root matches the previous slot's,
            // no block was proposed here.
            if slot_u64 > start_slot.as_u64()
                && let Ok(prev_root) = state.get_block_root(Slot::new(slot_u64 - 1))
                && prev_root == block_root
            {
                continue;
            }

            let blinded_block = db
                .get_blinded_block(block_root)
                .map_err(|error| format!("failed to load block: {error:?}"))?
                .ok_or_else(|| format!("missing block for root {block_root:?}"))?;
            let block = db
                .make_full_block(block_root, blinded_block)
                .map_err(|error| format!("failed to load block: {error:?}"))?;

            // Skip blocks whose actual slot is before this ERA's range. This handles
            // the boundary case: when the first slot of the range is missed,
            // get_block_root returns a block from the previous ERA's range.
            if block.slot() < start_slot {
                continue;
            }

            let compressed = CompressedSignedBeaconBlock::from_ssz(&block.as_ssz_bytes())
                .map_err(|error| format!("failed to compress block: {error:?}"))?;

            let data_len = compressed.data.len() as i64;
            let data_start = offset + 8;
            blocks.push(compressed);
            block_data_starts.push((slot, data_start));
            offset += 8 + data_len;
        }
    }

    let state_data_len = compressed_state.data.len() as i64;
    // Data starts after the 8-byte header.
    let state_data_start = offset + 8;
    offset += 8 + state_data_len;

    let block_index_start = offset;
    let slot_count = E::slots_per_historical_root();
    // SlotIndex layout: starting_slot (8) + offsets (slot_count * 8) + count (8).
    let block_index_len = 8 + slot_count as i64 * 8 + 8;
    if era_number > 0 {
        offset += 8 + block_index_len;
    }

    let state_index_start = offset;
    // Offset is relative to the start of the slot index data (after the 8-byte header)
    let state_offset = state_data_start - (state_index_start + 8);
    let state_slot_index = SlotIndex::new(end_slot.as_u64(), vec![state_offset]);

    let group = if era_number > 0 {
        let mut offsets = vec![0i64; slot_count];
        for (slot, data_start) in &block_data_starts {
            let slot_index = slot
                .as_u64()
                .checked_sub(start_slot.as_u64())
                .ok_or_else(|| "slot underflow while building block index".to_string())?
                as usize;
            offsets[slot_index] = *data_start - block_index_start;
        }
        let block_index = SlotIndex::new(start_slot.as_u64(), offsets);
        EraGroup::with_block_index(blocks, compressed_state, block_index, state_slot_index)
    } else {
        EraGroup::new(blocks, compressed_state, state_slot_index)
    };
    Ok(group)
}

fn short_historical_root<E: EthSpec>(
    state: &mut BeaconState<E>,
    era_number: u64,
) -> Result<[u8; 4], String> {
    let root = if era_number == 0 {
        state.genesis_validators_root()
    } else {
        let era_index = era_number
            .checked_sub(1)
            .ok_or_else(|| "era index underflow".to_string())?;
        let roots_len = state.historical_roots_mut().len();
        if era_index < roots_len as u64 {
            *state
                .historical_roots_mut()
                .get(era_index as usize)
                .ok_or_else(|| "historical root missing".to_string())?
        } else {
            let summary_index = era_index
                .checked_sub(roots_len as u64)
                .ok_or_else(|| "historical summary index underflow".to_string())?;
            let summaries = state
                .historical_summaries_mut()
                .map_err(|error| format!("failed to access historical summaries: {error:?}"))?;
            let summary = summaries
                .get(summary_index as usize)
                .ok_or_else(|| "historical summary missing".to_string())?;
            summary.tree_hash_root()
        }
    };

    let mut short_hash = [0u8; 4];
    short_hash.copy_from_slice(&root.as_slice()[..4]);
    Ok(short_hash)
}

/// Write an era file atomically using a temp file + rename.
///
/// If the process crashes mid-write, only the temp file is left behind; the final file is
/// created via rename, so it is either complete or absent. The era file existence check only
/// considers `.era` files, so partial temp files are ignored safely.
fn write_era_file_atomic(output_dir: &Path, file: &EraFile) -> Result<(), String> {
    let filename = file.id().to_file_name();
    let final_path = output_dir.join(&filename);
    if final_path.exists() {
        return Ok(());
    }

    // Create a unique temp file and write the full era contents into it.
    let tmp_name = format!("{filename}.tmp-{:016x}", random::<u64>());
    let tmp_path = output_dir.join(tmp_name);
    let mut file_handle = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .map_err(|error| format!("failed to create temp file: {error}"))?;
    {
        let mut writer = EraWriter::new(&mut file_handle);
        writer
            .write_file(file)
            .map_err(|error| format!("failed to write era file: {error:?}"))?;
    }
    file_handle
        .sync_all()
        .map_err(|error| format!("failed to fsync era temp file: {error}"))?;

    // Atomically publish; if another writer won, clean up and exit.
    if let Err(error) = fs::rename(&tmp_path, &final_path) {
        if error.kind() == std::io::ErrorKind::AlreadyExists && final_path.exists() {
            let _ = fs::remove_file(&tmp_path);
            return Ok(());
        }
        return Err(format!("failed to rename era temp file: {error}"));
    }

    // Best-effort directory sync to make the rename durable.
    if let Ok(dir_handle) = File::open(output_dir) {
        let _ = dir_handle.sync_all();
    }

    Ok(())
}

fn era_file_id<E: EthSpec>(
    network_name: &str,
    era_number: u64,
    state: &mut BeaconState<E>,
) -> Result<EraId, String> {
    // reth_era uses hardcoded SLOTS_PER_HISTORICAL_ROOT=8192 to compute era number from start_slot.
    // To get the correct filename era number, we pass era_number * 8192 as the start_slot.
    const RETH_SLOTS_PER_HISTORICAL_ROOT: u64 = 8192;
    let reth_start_slot = era_number * RETH_SLOTS_PER_HISTORICAL_ROOT;

    let slot_count = if era_number == 0 {
        0
    } else {
        E::slots_per_historical_root() as u32
    };
    let short_hash = short_historical_root(state, era_number)?;
    Ok(EraId::new(network_name, reth_start_slot, slot_count).with_hash(short_hash))
}
