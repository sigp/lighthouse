//! Slot-indexed, append-only static file storage.
//!
//! `StaticFile` owns one directory containing:
//!
//! ```text
//! <root>/
//!   data_{file_id:05}         # file_id = slot / SLOTS_PER_FILE
//!   data_{file_id:05}.off     # SLOTS_PER_FILE × u64 LE offsets, 0 = no record
//!   column.conf               # 34-byte commit marker, atomic-renamed
//! ```
//!
//! # File format
//!
//! Data file: `b"LHSF"`, then records appended as `length[4 LE] | payload`.
//!
//! `column.conf`: `b"LHSF" | version u32 LE | highest_slot u64 LE (u64::MAX =
//! empty) | current_data_len u64 LE`.
//! Atomic update: write `.tmp`, fsync, rename, fsync dir.
//!
//! # Put contract
//!
//! Durable on return. Slots arrive ascending **or** are identical-value
//! re-puts of an already-committed slot (so migration retries after a
//! mid-loop crash are safe). Previously-skipped slots (offset 0) cannot
//! be filled — that would break the append-only data file. A failed write
//! poisons the handle: further writes error until reopen; reads stay live.
//!
//! # Recovery on open
//!
//! Data file truncated to `current_data_len`; `.off` entries beyond
//! `highest_slot` cleared; files beyond the committed file removed. The
//! `column.conf` rename is the commit point.

use parking_lot::Mutex;
use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

/// 8192-slot chunks; 8192 offsets fit in 64 KiB.
pub const SLOTS_PER_FILE: u64 = 8192;
type SlotGroup<'a> = (u64, Vec<(u64, &'a [u8])>);

const OFFSET_SIZE: u64 = 8;
const OFFSET_FILE_LEN: u64 = SLOTS_PER_FILE * OFFSET_SIZE;
const CONFIG_FILE: &str = "column.conf";
const CONFIG_TMP_FILE: &str = "column.conf.tmp";
const DATA_FILE_PREFIX: &str = "data_";
/// Config file identity. Format revisions bump `FORMAT_VERSION`, not this.
const CONFIG_MAGIC: &[u8; 4] = b"LHSF";
/// On-disk format version. Bump on any breaking layout change (implies a rebuild).
const FORMAT_VERSION: u32 = 1;
/// Empty-store sentinel for `highest_written_slot` in the per-file config.
const EMPTY_SLOT: u64 = u64::MAX;
/// Header marker, written once at the start of each data file.
const DATA_FILE_HEADER: [u8; 4] = *b"LHSF";

/// Last durable `column.conf` marker.
#[derive(Debug, Clone, Copy)]
struct CommittedState {
    /// Highest committed slot, or `None` when empty.
    highest_slot: Option<u64>,
    /// Committed end of the file containing `highest_slot`.
    data_len: u64,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "static file io error: {e}"),
            Self::Invalid(message) => write!(f, "static file invalid data: {message}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Invalid(_) => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Slot-keyed file set. Owns one directory of `data_*`, `data_*.off`, and
/// `column.conf` files.
#[derive(Debug)]
pub struct StaticFile {
    root_dir: PathBuf,
    /// Max record size, an OOM guard on reads.
    max_value_bytes: u64,
    // Writer holds this across put_batch's fsyncs, so readers block. Accepted:
    // simplicity over read concurrency.
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    /// Highest committed slot and committed data length from `column.conf`.
    committed: CommittedState,
    /// Set when a write error leaves on-disk state unverified; further writes
    /// error until reopen. Reads stay safe: `committed` never runs ahead of disk.
    poisoned: bool,
}

impl StaticFile {
    /// Open or create a `StaticFile` rooted at `root_dir`. `max_value_bytes` is
    /// a runtime-only read OOM cap. The column is identified by its directory.
    pub fn open(root_dir: PathBuf, max_value_bytes: u64) -> Result<Self, Error> {
        fs::create_dir_all(&root_dir)?;
        let config_path = root_dir.join(CONFIG_FILE);
        let tmp_path = root_dir.join(CONFIG_TMP_FILE);

        let committed = if config_path.exists() {
            deserialize_on_disk_config(&fs::read(&config_path)?)?
        } else {
            // A store writes column.conf before any data file, so data files
            // without a conf mean external damage — don't wipe them.
            if dir_has_static_files(&root_dir)? {
                return Err(Error::Invalid(format!(
                    "column.conf missing but data files exist in {}",
                    root_dir.display()
                )));
            }
            atomic_write_config(&config_path, &tmp_path, &root_dir, None, 0)?;
            CommittedState {
                highest_slot: None,
                data_len: 0,
            }
        };

        let handle = Self {
            root_dir,
            max_value_bytes,
            state: Mutex::new(State {
                committed,
                poisoned: false,
            }),
        };
        handle.heal_to_marker(committed.highest_slot, committed.data_len)?;
        Ok(handle)
    }

    /// Slot of the most recently committed record, if any.
    fn highest_written_slot(&self) -> Option<u64> {
        self.state.lock().committed.highest_slot
    }

    /// Read the record at `slot`, if present.
    pub fn get(&self, slot: u64) -> Result<Option<Vec<u8>>, Error> {
        if self.highest_written_slot().is_none_or(|h| slot > h) {
            return Ok(None);
        }
        self.read_record(slot)
    }

    /// `true` if a record exists at `slot`. Cheaper than `get` — only the
    /// `.off` sidecar is consulted; the data file is not read.
    pub fn contains(&self, slot: u64) -> Result<bool, Error> {
        if self.highest_written_slot().is_none_or(|h| slot > h) {
            return Ok(false);
        }
        Ok(self.read_offset(file_id(slot), slot)? != 0)
    }

    /// Durably store `bytes` at `slot`. Slots must arrive strictly ascending,
    /// or be an identical-value re-put of a previously committed slot
    /// (re-puts at any committed slot are idempotent so migration retries
    /// after a mid-loop crash are safe). A previously-skipped slot (offset
    /// zero) cannot be filled — that would break the append-only data file.
    pub fn put(&self, slot: u64, bytes: &[u8]) -> Result<(), Error> {
        self.put_batch(vec![(slot, bytes)])
    }

    /// Append `items` with one fsync per file (data + offset), not per slot.
    /// Whole batch is durable on return — the same caller-visible contract as
    /// `put` — but with O(1) syncs per underlying file instead of O(n) per
    /// item. Items must be strictly ascending. Already-committed prefix items
    /// are treated as idempotent re-puts if their bytes match, then skipped.
    pub fn put_batch(&self, items: Vec<(u64, &[u8])>) -> Result<(), Error> {
        let Some((last_slot, _)) = items.last() else {
            return Ok(());
        };
        for w in items.windows(2) {
            if w[1].0 <= w[0].0 {
                return Err(Error::Invalid(
                    "put_batch slots must be strictly ascending".into(),
                ));
            }
        }
        if *last_slot == EMPTY_SLOT {
            return Err(Error::Invalid("slot u64::MAX is reserved".into()));
        }

        let mut state = self.state.lock();
        if state.poisoned {
            return Err(Error::Invalid(
                "writes rejected after an earlier write failure; reopen to heal".into(),
            ));
        }
        let start = self.skip_committed_prefix(&items, state.committed.highest_slot)?;
        if start == items.len() {
            // Avoid rewriting config with no fresh data_len.
            return Ok(());
        }

        // Group remaining items by file_id, write each group with one
        // data fsync + one offset fsync. Single config commit at end of batch.
        // Fail-stop: any error past this point leaves on-disk state unverified
        // (stale offsets, or a conf rename that landed despite the Err), so
        // poison writes and let open-time healing recover. Reads stay safe:
        // `committed` never runs ahead of disk.
        let mut last_data_len: u64 = 0;
        for (target_file_id, group) in group_by_file_id(&items[start..]) {
            match self.write_group(target_file_id, &group, state.committed) {
                Ok(data_len) => last_data_len = data_len,
                Err(e) => {
                    state.poisoned = true;
                    return Err(e);
                }
            }
        }

        if let Err(e) = self.write_config(Some(*last_slot), last_data_len) {
            state.poisoned = true;
            return Err(e);
        }
        state.committed = CommittedState {
            highest_slot: Some(*last_slot),
            data_len: last_data_len,
        };
        Ok(())
    }

    /// Validate already-committed retry items and return the first new item.
    /// This lets migration retries overlap with the committed prefix without
    /// rewriting offsets or filling skipped slots.
    fn skip_committed_prefix(
        &self,
        items: &[(u64, &[u8])],
        highest_written_slot: Option<u64>,
    ) -> Result<usize, Error> {
        let Some(highest) = highest_written_slot else {
            return Ok(0);
        };

        let mut start = 0;
        while start < items.len() && items[start].0 <= highest {
            let (slot, value) = &items[start];
            let existing = self.read_record(*slot)?.ok_or_else(|| {
                Error::Invalid(format!(
                    "re-put at slot {slot} <= highest {highest} but no record exists; \
                     cannot fill a previously-skipped slot"
                ))
            })?;
            if existing.as_slice() != *value {
                return Err(Error::Invalid(format!(
                    "re-put at slot {slot} with mismatched value"
                )));
            }
            start += 1;
        }
        Ok(start)
    }

    /// Write `group` (all in `target_file_id`) to disk: append records, fsync
    /// the data file, write all offsets, fsync the offset file. Returns the
    /// committed data file length. Does NOT update `highest_written_slot` or
    /// `column.conf` — the caller commits via `write_config` after this.
    fn write_group(
        &self,
        target_file_id: u64,
        group: &[(u64, &[u8])],
        committed: CommittedState,
    ) -> Result<u64, Error> {
        let data_path = self.data_path(target_file_id);
        let off_path = self.offset_path(target_file_id);

        let mut data_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false) // keep committed records; we seek + overwrite
            .open(&data_path)?;
        let cursor = if committed
            .highest_slot
            .is_some_and(|slot| file_id(slot) == target_file_id)
        {
            committed.data_len
        } else {
            // new file: plant header at offset 0, start just past it
            data_file.seek(SeekFrom::Start(0))?;
            data_file.write_all(&DATA_FILE_HEADER)?;
            DATA_FILE_HEADER.len() as u64
        };
        let data_len = data_file.metadata()?.len();
        if data_len < cursor {
            return Err(Error::Invalid(
                "data file shorter than committed length".into(),
            ));
        }
        if data_len != cursor {
            data_file.set_len(cursor)?;
        }
        data_file.seek(SeekFrom::Start(cursor))?;

        let mut offsets = Vec::with_capacity(group.len());
        {
            // 1 MiB batches tiny record writes during imports.
            let mut writer = std::io::BufWriter::with_capacity(1 << 20, &mut data_file);
            let mut next_offset = cursor;
            for &(slot, value) in group {
                if (value.len() as u64) > self.max_value_bytes {
                    return Err(Error::Invalid("record exceeds size limit".into()));
                }
                let payload_len = u32::try_from(value.len())
                    .map_err(|_| Error::Invalid("record too large".into()))?;
                offsets.push((slot, next_offset));
                writer.write_all(&payload_len.to_le_bytes())?; // len[4]
                next_offset += 4;
                writer.write_all(value)?; // payload
                next_offset += value.len() as u64;
            }
            writer.flush()?;
        }
        let data_len = data_file.seek(SeekFrom::End(0))?;
        // Data must hit disk before offsets, both before config commit.
        data_file.sync_all()?;

        let mut off_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&off_path)?;
        // Pre-size so skipped slots read as zero offsets.
        if off_file.metadata()?.len() < OFFSET_FILE_LEN {
            off_file.set_len(OFFSET_FILE_LEN)?;
        }
        for (slot, offset) in &offsets {
            off_file.seek(SeekFrom::Start(offset_position(*slot)))?;
            off_file.write_all(&offset.to_le_bytes())?;
        }
        off_file.sync_all()?;

        Ok(data_len)
    }

    /// Read a record at `slot` without consulting the writer mutex. Used by
    /// callers that already hold the lock (`put` for the idempotency check).
    fn read_record(&self, slot: u64) -> Result<Option<Vec<u8>>, Error> {
        let file_id = file_id(slot);
        let offset = self.read_offset(file_id, slot)?;
        if offset == 0 {
            return Ok(None);
        }

        let data_path = self.data_path(file_id);
        let mut data_file = File::open(&data_path)?;
        data_file.seek(SeekFrom::Start(offset))?;

        let mut header = [0; 4];
        data_file.read_exact(&mut header)?;
        let len = u32::from_le_bytes(header);
        if u64::from(len) > self.max_value_bytes {
            return Err(Error::Invalid("record exceeds size limit".into()));
        }

        let len = len as usize;
        let mut payload = vec![0; len];
        data_file.read_exact(&mut payload)?;
        Ok(Some(payload))
    }

    /// Restore files to the committed marker and remove future crash leftovers.
    fn heal_to_marker(
        &self,
        highest_written_slot: Option<u64>,
        current_data_len: u64,
    ) -> Result<(), Error> {
        if let Some(slot) = highest_written_slot {
            self.heal_current_file(slot, current_data_len)?;
            self.remove_uncommitted_files(Some(file_id(slot)))
        } else {
            self.remove_uncommitted_files(None)
        }
    }

    /// Truncate the committed file back to the config marker after a crash.
    /// Data beyond `current_data_len` and offsets beyond `slot` are uncommitted.
    fn heal_current_file(&self, slot: u64, current_data_len: u64) -> Result<(), Error> {
        let file_id = file_id(slot);
        let data_path = self.data_path(file_id);
        let data_file = OpenOptions::new().read(true).write(true).open(&data_path)?;
        let data_len = data_file.metadata()?.len();
        if data_len < current_data_len {
            return Err(Error::Invalid(
                "data file shorter than committed length".into(),
            ));
        }
        if data_len != current_data_len {
            data_file.set_len(current_data_len)?;
            data_file.sync_all()?;
        }

        let off_path = self.offset_path(file_id);
        let mut off_file = OpenOptions::new().read(true).write(true).open(&off_path)?;
        let required_len = offset_position(slot) + OFFSET_SIZE;
        let off_len = off_file.metadata()?.len();
        if off_len < required_len {
            return Err(Error::Invalid(
                "offset file shorter than committed slot".into(),
            ));
        }
        if off_len < OFFSET_FILE_LEN {
            off_file.set_len(OFFSET_FILE_LEN)?;
        }

        let clear_start = required_len;
        if clear_start < OFFSET_FILE_LEN {
            // Remove offsets to entries beyond the committed slot.
            off_file.seek(SeekFrom::Start(clear_start))?;
            let zeroes = vec![0; (OFFSET_FILE_LEN - clear_start) as usize];
            off_file.write_all(&zeroes)?;
            off_file.sync_all()?;
        }

        Ok(())
    }

    /// Remove data/offset files newer than the committed file id.
    /// `None` means the store is empty, so every data/offset file is removed.
    fn remove_uncommitted_files(&self, max_file_id: Option<u64>) -> Result<(), Error> {
        let mut removed = false;
        for entry in fs::read_dir(&self.root_dir)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let Some(file_name) = file_name.to_str() else {
                continue;
            };
            let Some(file_id) = static_file_id(file_name) else {
                continue;
            };
            if max_file_id.is_none_or(|max| file_id > max) {
                let file_type = entry.file_type()?;
                if !file_type.is_file() {
                    return Err(Error::Invalid(format!(
                        "static data path is not a file: {}",
                        entry.path().display()
                    )));
                }
                fs::remove_file(entry.path())?;
                removed = true;
            }
        }
        if removed {
            sync_dir(&self.root_dir)?;
        }
        Ok(())
    }

    /// Atomically publish the commit marker after data and offsets are durable.
    fn write_config(
        &self,
        highest_written_slot: Option<u64>,
        current_data_len: u64,
    ) -> Result<(), Error> {
        atomic_write_config(
            &self.config_path(),
            &self.root_dir.join(CONFIG_TMP_FILE),
            &self.root_dir,
            highest_written_slot,
            current_data_len,
        )
    }

    fn read_offset(&self, file_id: u64, slot: u64) -> Result<u64, Error> {
        let off_path = self.offset_path(file_id);
        let mut off_file = match File::open(&off_path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        let mut bytes = [0; 8];
        off_file.seek(SeekFrom::Start(offset_position(slot)))?;
        off_file.read_exact(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn config_path(&self) -> PathBuf {
        self.root_dir.join(CONFIG_FILE)
    }

    fn data_path(&self, file_id: u64) -> PathBuf {
        self.root_dir
            .join(format!("{DATA_FILE_PREFIX}{file_id:05}"))
    }

    fn offset_path(&self, file_id: u64) -> PathBuf {
        self.root_dir
            .join(format!("{DATA_FILE_PREFIX}{file_id:05}.off"))
    }
}

/// Pack the 24-byte `column.conf` marker.
fn serialize_on_disk_config(committed: CommittedState) -> Vec<u8> {
    let mut bytes = vec![0u8; 24];
    bytes[0..4].copy_from_slice(CONFIG_MAGIC);
    bytes[4..8].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes[8..16].copy_from_slice(&committed.highest_slot.unwrap_or(EMPTY_SLOT).to_le_bytes());
    bytes[16..24].copy_from_slice(&committed.data_len.to_le_bytes());
    bytes
}

/// Parse the 24-byte `column.conf` marker.
fn deserialize_on_disk_config(bytes: &[u8]) -> Result<CommittedState, Error> {
    if bytes.len() != 24 {
        return Err(Error::Invalid("invalid config length".into()));
    }
    if &bytes[0..4] != CONFIG_MAGIC {
        return Err(Error::Invalid("invalid config magic".into()));
    }
    let version = u32::from_le_bytes(bytes[4..8].try_into().expect("slice length checked"));
    if version != FORMAT_VERSION {
        return Err(Error::Invalid(format!(
            "unsupported config version {version}, expected {FORMAT_VERSION}"
        )));
    }
    let highest = u64::from_le_bytes(bytes[8..16].try_into().expect("slice length checked"));
    let data_len = u64::from_le_bytes(bytes[16..24].try_into().expect("slice length checked"));
    Ok(CommittedState {
        highest_slot: (highest != EMPTY_SLOT).then_some(highest),
        data_len,
    })
}

/// Write `column.conf.tmp`, fsync it, rename over `column.conf`, then fsync
/// the directory so the rename is durable.
fn atomic_write_config(
    config_path: &Path,
    tmp_path: &Path,
    root_dir: &Path,
    highest_written_slot: Option<u64>,
    current_data_len: u64,
) -> Result<(), Error> {
    let bytes = serialize_on_disk_config(CommittedState {
        highest_slot: highest_written_slot,
        data_len: current_data_len,
    });

    {
        let mut tmp = File::create(tmp_path)?;
        tmp.write_all(&bytes)?;
        tmp.sync_all()?;
    }

    fs::rename(tmp_path, config_path)?;
    sync_dir(root_dir)
}

fn file_id(slot: u64) -> u64 {
    slot / SLOTS_PER_FILE
}

fn offset_position(slot: u64) -> u64 {
    (slot % SLOTS_PER_FILE) * OFFSET_SIZE
}

fn static_file_id(file_name: &str) -> Option<u64> {
    let suffix = file_name.strip_prefix(DATA_FILE_PREFIX)?;
    let id = suffix.strip_suffix(".off").unwrap_or(suffix);
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    id.parse().ok()
}

/// `true` if `root_dir` contains any data or offset file.
fn dir_has_static_files(root_dir: &Path) -> Result<bool, Error> {
    for entry in fs::read_dir(root_dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        if static_file_id(file_name).is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Convert an ascending slot list into consecutive groups for each data file.
fn group_by_file_id<'a>(items: &[(u64, &'a [u8])]) -> Vec<SlotGroup<'a>> {
    let mut groups = Vec::new();
    let mut current_file_id = None;
    let mut current_group = Vec::new();

    for (slot, value) in items {
        let target_file_id = file_id(*slot);
        if current_file_id == Some(target_file_id) {
            current_group.push((*slot, *value));
        } else {
            if let Some(file_id) = current_file_id {
                groups.push((file_id, current_group));
                current_group = Vec::new();
            }
            current_file_id = Some(target_file_id);
            current_group.push((*slot, *value));
        }
    }

    if let Some(file_id) = current_file_id {
        groups.push((file_id, current_group));
    }

    groups
}

#[cfg(not(windows))]
fn sync_dir(path: &Path) -> Result<(), Error> {
    let dir = File::open(path)?;
    dir.sync_all()?;
    Ok(())
}

/// Windows can't open directories to fsync them; NTFS journals metadata ops.
#[cfg(windows)]
fn sync_dir(_path: &Path) -> Result<(), Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_VALUE_BYTES: u64 = 1024;

    fn open(dir: &tempfile::TempDir) -> StaticFile {
        StaticFile::open(dir.path().to_path_buf(), MAX_VALUE_BYTES).unwrap()
    }

    #[test]
    fn round_trip_sparse_slots() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir);

        store.put(100, b"a").unwrap();
        store.put(9000, b"b").unwrap();

        assert_eq!(store.get(100).unwrap(), Some(b"a".to_vec()));
        assert_eq!(store.get(101).unwrap(), None);
        assert_eq!(store.get(9000).unwrap(), Some(b"b".to_vec()));
        assert!(!store.contains(101).unwrap());
    }

    #[test]
    fn reopen_preserves_committed_records() {
        let dir = tempfile::tempdir().unwrap();
        open(&dir)
            .put_batch(vec![(SLOTS_PER_FILE - 1, b"a"), (SLOTS_PER_FILE, b"b")])
            .unwrap();

        let store = open(&dir);
        assert_eq!(store.get(SLOTS_PER_FILE - 1).unwrap(), Some(b"a".to_vec()));
        assert_eq!(store.get(SLOTS_PER_FILE).unwrap(), Some(b"b".to_vec()));
    }

    #[test]
    fn batch_retries_committed_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir);

        store.put_batch(vec![(0, b"a"), (1, b"b")]).unwrap();
        store
            .put_batch(vec![(0, b"a"), (1, b"b"), (2, b"c")])
            .unwrap();

        assert_eq!(store.get(2).unwrap(), Some(b"c".to_vec()));
        assert!(store.put_batch(vec![(1, b"wrong")]).is_err());
    }

    #[test]
    fn open_removes_uncommitted_future_file() {
        let dir = tempfile::tempdir().unwrap();
        open(&dir).put(0, b"a").unwrap();
        fs::write(dir.path().join("data_00001"), b"stale").unwrap();
        fs::write(dir.path().join("data_00001.off"), b"stale").unwrap();

        let store = open(&dir);
        assert!(!dir.path().join("data_00001").exists());
        assert!(!dir.path().join("data_00001.off").exists());

        store.put(SLOTS_PER_FILE, b"b").unwrap();
        assert_eq!(store.get(SLOTS_PER_FILE).unwrap(), Some(b"b".to_vec()));
    }

    #[test]
    fn max_slot_is_reserved() {
        let dir = tempfile::tempdir().unwrap();
        assert!(open(&dir).put(u64::MAX, b"x").is_err());
    }

    #[test]
    fn write_failure_poisons_writes_until_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir);
        store.put(0, b"a").unwrap();

        let oversized = vec![0u8; (MAX_VALUE_BYTES + 1) as usize];
        assert!(store.put_batch(vec![(1, b"b"), (2, &oversized)]).is_err());

        // writes rejected, reads still served
        assert!(store.put(3, b"c").is_err());
        assert_eq!(store.get(0).unwrap(), Some(b"a".to_vec()));

        // reopen heals and lifts the poison
        drop(store);
        let store = open(&dir);
        store.put(3, b"c").unwrap();
        assert_eq!(store.get(3).unwrap(), Some(b"c".to_vec()));
    }

    #[test]
    fn missing_conf_with_data_files_errors() {
        let dir = tempfile::tempdir().unwrap();
        open(&dir)
            .put_batch(vec![(0, b"a"), (SLOTS_PER_FILE, b"b")])
            .unwrap();
        fs::remove_file(dir.path().join("column.conf")).unwrap();

        assert!(StaticFile::open(dir.path().to_path_buf(), MAX_VALUE_BYTES).is_err());
        assert!(dir.path().join("data_00000").exists());
        assert!(dir.path().join("data_00001").exists());
    }

    /// Forge a record + offset for `slot` without committing `column.conf`,
    /// mimicking a crash after the data/offset fsyncs but before the marker.
    fn forge_uncommitted(dir: &tempfile::TempDir, file_id: u64, slot: u64, at: u64, value: &[u8]) {
        let data = dir.path().join(format!("data_{file_id:05}"));
        let off = dir.path().join(format!("data_{file_id:05}.off"));
        let mut d = OpenOptions::new().append(true).open(&data).unwrap();
        d.write_all(&(value.len() as u32).to_le_bytes()).unwrap();
        d.write_all(value).unwrap();
        let mut o = OpenOptions::new().write(true).open(&off).unwrap();
        o.seek(SeekFrom::Start(offset_position(slot))).unwrap();
        o.write_all(&at.to_le_bytes()).unwrap();
    }

    // A torn append (data + offset written, marker not) is rolled back on open,
    // leaving committed records intact and no phantom record.
    #[test]
    fn reopen_truncates_torn_append() {
        let dir = tempfile::tempdir().unwrap();
        open(&dir).put_batch(vec![(0, b"a"), (1, b"b")]).unwrap();
        let data = dir.path().join("data_00000");
        let committed_len = fs::metadata(&data).unwrap().len();
        forge_uncommitted(&dir, 0, 2, committed_len, b"Z");

        let store = open(&dir);
        assert_eq!(store.get(0).unwrap(), Some(b"a".to_vec()));
        assert_eq!(store.get(1).unwrap(), Some(b"b".to_vec()));
        assert_eq!(store.get(2).unwrap(), None);
        assert_eq!(fs::metadata(&data).unwrap().len(), committed_len);
    }

    // A torn multi-file batch (appended to the committed file and created a new
    // one, marker not updated) rolls back wholesale on open.
    #[test]
    fn reopen_rolls_back_torn_multifile_batch() {
        let dir = tempfile::tempdir().unwrap();
        open(&dir).put(0, b"a").unwrap();
        let data0 = dir.path().join("data_00000");
        let committed_len = fs::metadata(&data0).unwrap().len();
        forge_uncommitted(&dir, 0, 1, committed_len, b"b");
        fs::write(dir.path().join("data_00001"), b"garbage").unwrap();
        fs::write(
            dir.path().join("data_00001.off"),
            vec![0u8; OFFSET_FILE_LEN as usize],
        )
        .unwrap();

        let store = open(&dir);
        assert_eq!(store.get(0).unwrap(), Some(b"a".to_vec()));
        assert_eq!(store.get(1).unwrap(), None);
        assert_eq!(fs::metadata(&data0).unwrap().len(), committed_len);
        assert!(!dir.path().join("data_00001").exists());
    }
}
