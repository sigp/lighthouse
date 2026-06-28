//! Slot-indexed, append-only static file storage.
//!
//! `StaticFile` owns one directory containing:
//!
//! ```text
//! <root>/
//!   data_{file_id:05}         # file_id = slot / SLOTS_PER_FILE
//!   data_{file_id:05}.off     # SLOTS_PER_FILE × u64 LE offsets, 0 = no record
//!   column.conf               # 36-byte commit marker, atomic-renamed
//! ```
//!
//! # File format
//!
//! Data file: e2store version record (`65 32 00 00 00 00 00 00`), then records
//! appended as `type[2] | length[4 LE] | reserved[2]=0 | payload`.
//!
//! `column.conf`: `b"LHSTBLK3" | highest_slot u64 LE (u64::MAX = empty) |
//! current_data_len u64 LE | record_type[2] | max_value_bytes u64 LE`.
//! Atomic update: write `.tmp`, fsync, rename, fsync dir.
//!
//! # Put contract
//!
//! Durable on return. Slots arrive ascending **or** are identical-value
//! re-puts of an already-committed slot (so migration retries after a
//! mid-loop crash are safe). Previously-skipped slots (offset 0) cannot
//! be filled — that would break the append-only data file.
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

pub const SLOTS_PER_FILE: u64 = 8192;
type SlotGroup<'a> = (u64, Vec<(u64, &'a [u8])>);

const OFFSET_SIZE: u64 = 8;
const OFFSET_FILE_LEN: u64 = SLOTS_PER_FILE * OFFSET_SIZE;
const CONFIG_FILE: &str = "column.conf";
const CONFIG_TMP_FILE: &str = "column.conf.tmp";
const DATA_FILE_PREFIX: &str = "data_";
const CONFIG_MAGIC: &[u8; 8] = b"LHSTBLK3";
const CONFIG_LEN: usize = 34;
const CONFIG_DATA_START: usize = 24;
const CONFIG_DATA_LEN: usize = 10;
/// Empty-store sentinel for `highest_written_slot` in the per-file config.
const EMPTY_SLOT: u64 = u64::MAX;
/// e2store version record, written once at the start of each data file.
const VERSION_RECORD: [u8; 8] = [0x65, 0x32, 0, 0, 0, 0, 0, 0];
/// e2store record header reserved bytes.
const RECORD_RESERVED: [u8; 2] = [0, 0];

/// On-disk format settings for one `StaticFile`. Persisted on first creation;
/// on re-open the on-disk values must match what the caller passes in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// e2store record type tag.
    pub record_type: [u8; 2],
    /// Upper bound on a single stored record's size in bytes.
    pub max_value_bytes: u64,
}

impl Config {
    fn serialize(&self) -> [u8; CONFIG_DATA_LEN] {
        let mut bytes = [0u8; CONFIG_DATA_LEN];
        bytes[0..2].copy_from_slice(&self.record_type);
        bytes[2..10].copy_from_slice(&self.max_value_bytes.to_le_bytes());
        bytes
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != CONFIG_DATA_LEN {
            return Err(Error::Invalid("invalid config data length".into()));
        }
        let record_type = [bytes[0], bytes[1]];
        let max_value_bytes =
            u64::from_le_bytes(bytes[2..10].try_into().expect("slice length checked"));
        Ok(Self {
            record_type,
            max_value_bytes,
        })
    }
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
    config: Config,
    /// `None` = empty store, `Some(s)` = highest committed slot.
    /// Persisted as `u64::MAX` (`EMPTY_SLOT`) when `None`.
    highest_written_slot: Mutex<Option<u64>>,
}

impl StaticFile {
    /// Open or create a `StaticFile` rooted at `root_dir`. On first creation,
    /// `config` is persisted. On re-open, the persisted config must equal
    /// `config` — any mismatch is a startup error.
    pub fn open(root_dir: PathBuf, config: Config) -> Result<Self, Error> {
        fs::create_dir_all(&root_dir)?;
        let config_path = root_dir.join(CONFIG_FILE);
        let tmp_path = root_dir.join(CONFIG_TMP_FILE);

        let (highest, data_len) = if config_path.exists() {
            let (highest, data_len, on_disk) = read_config(&config_path)?;
            if on_disk != config {
                return Err(Error::Invalid(format!(
                    "config mismatch: on-disk {on_disk:?}, build {config:?}"
                )));
            }
            (highest, data_len)
        } else {
            atomic_write_config(&config_path, &tmp_path, &root_dir, None, 0, &config)?;
            (None, 0)
        };

        let handle = Self {
            root_dir,
            config,
            highest_written_slot: Mutex::new(highest),
        };
        handle.heal_to_marker(highest, data_len)?;
        Ok(handle)
    }

    /// Slot of the most recently committed record, if any.
    fn highest_written_slot(&self) -> Option<u64> {
        *self.highest_written_slot.lock()
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

        let mut highest_written_slot = self.highest_written_slot.lock();
        let start = self.skip_committed_prefix(&items, *highest_written_slot)?;
        if start == items.len() {
            return Ok(());
        }

        // Group remaining items by file_id, write each group with one
        // data fsync + one offset fsync. Single config commit at end of batch.
        let mut last_data_len: u64 = 0;
        for (target_file_id, group) in group_by_file_id(&items[start..]) {
            match self.write_group(target_file_id, &group) {
                Ok(data_len) => last_data_len = data_len,
                Err(e) => {
                    if let Ok(committed_highest) = self.heal_from_config() {
                        *highest_written_slot = committed_highest;
                    }
                    return Err(e);
                }
            }
        }

        if let Err(e) = self.write_config(Some(*last_slot), last_data_len) {
            if let Ok(committed_highest) = self.heal_from_config() {
                *highest_written_slot = committed_highest;
            }
            return Err(e);
        }
        *highest_written_slot = Some(*last_slot);
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
    fn write_group(&self, target_file_id: u64, group: &[(u64, &[u8])]) -> Result<u64, Error> {
        let data_path = self.data_path(target_file_id);
        let off_path = self.offset_path(target_file_id);

        let mut data_file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&data_path)?;
        if data_file.metadata()?.len() == 0 {
            data_file.write_all(&VERSION_RECORD)?;
        }

        let mut cursor = data_file.metadata()?.len();
        let offsets = group
            .iter()
            .map(|(slot, value)| {
                let offset = cursor;
                cursor += 8 + value.len() as u64;
                (*slot, offset)
            })
            .collect::<Vec<_>>();

        {
            // BufWriter coalesces the 8-byte record headers + payloads into
            // larger syscalls; cheap for one record, load-bearing for batches.
            let mut writer = std::io::BufWriter::with_capacity(1 << 20, &mut data_file);
            for (_, value) in group {
                if (value.len() as u64) > self.config.max_value_bytes {
                    return Err(Error::Invalid("record exceeds size limit".into()));
                }
                let payload_len = u32::try_from(value.len())
                    .map_err(|_| Error::Invalid("record too large".into()))?;
                writer.write_all(&self.config.record_type)?;
                writer.write_all(&payload_len.to_le_bytes())?;
                writer.write_all(&RECORD_RESERVED)?;
                writer.write_all(value)?;
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

        let mut header = [0; 8];
        data_file.read_exact(&mut header)?;
        if header[0..2] != self.config.record_type || header[6..8] != RECORD_RESERVED {
            return Err(Error::Invalid("invalid record header".into()));
        }

        let len = u32::from_le_bytes([header[2], header[3], header[4], header[5]]);
        if u64::from(len) > self.config.max_value_bytes {
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

    /// Re-read `column.conf` and restore files to whatever marker is durable.
    fn heal_from_config(&self) -> Result<Option<u64>, Error> {
        let (highest, data_len, on_disk) = read_config(&self.config_path())?;
        if on_disk != self.config {
            return Err(Error::Invalid(format!(
                "config mismatch: on-disk {on_disk:?}, build {:?}",
                self.config
            )));
        }
        self.heal_to_marker(highest, data_len)?;
        Ok(highest)
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
            &self.config,
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

/// Returns (highest_written_slot, current_data_len, on-disk config).
fn read_config(path: &Path) -> Result<(Option<u64>, u64, Config), Error> {
    let bytes = fs::read(path)?;
    if bytes.len() != CONFIG_LEN || &bytes[0..8] != CONFIG_MAGIC {
        return Err(Error::Invalid("invalid config".into()));
    }
    let highest = u64::from_le_bytes(bytes[8..16].try_into().expect("slice length checked"));
    let current_data_len =
        u64::from_le_bytes(bytes[16..24].try_into().expect("slice length checked"));
    let config = Config::deserialize(&bytes[CONFIG_DATA_START..])?;
    Ok((
        (highest != EMPTY_SLOT).then_some(highest),
        current_data_len,
        config,
    ))
}

/// Write `column.conf.tmp`, fsync it, rename over `column.conf`, then fsync
/// the directory so the rename is durable.
fn atomic_write_config(
    config_path: &Path,
    tmp_path: &Path,
    root_dir: &Path,
    highest_written_slot: Option<u64>,
    current_data_len: u64,
    config: &Config,
) -> Result<(), Error> {
    let mut bytes = [0u8; CONFIG_LEN];
    bytes[0..8].copy_from_slice(CONFIG_MAGIC);
    bytes[8..16].copy_from_slice(&highest_written_slot.unwrap_or(EMPTY_SLOT).to_le_bytes());
    bytes[16..24].copy_from_slice(&current_data_len.to_le_bytes());
    bytes[CONFIG_DATA_START..].copy_from_slice(&config.serialize());

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

fn sync_dir(path: &Path) -> Result<(), Error> {
    let dir = File::open(path)?;
    dir.sync_all()?;
    Ok(())
}
