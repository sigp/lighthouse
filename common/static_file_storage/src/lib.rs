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
//! appended as `type[2] | length[4 LE] | reserved[2]=0 | payload` (snappy-
//! framed if `Config::compression`).
//!
//! `column.conf`: `b"LHSTBLK2" | highest_slot u64 LE (u64::MAX = empty) |
//! current_data_len u64 LE | record_type[2] | compression u8 | reserved | max_value_bytes u64 LE`.
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
//! `highest_slot` cleared. The `column.conf` rename is the commit point.

use parking_lot::Mutex;
use snap::{read::FrameDecoder, write::FrameEncoder};
use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

pub const SLOTS_PER_FILE: u64 = 8192;
const OFFSET_SIZE: u64 = 8;
const OFFSET_FILE_LEN: u64 = SLOTS_PER_FILE * OFFSET_SIZE;
const CONFIG_FILE: &str = "column.conf";
const CONFIG_TMP_FILE: &str = "column.conf.tmp";
const DATA_FILE_PREFIX: &str = "data_";
const CONFIG_MAGIC: &[u8; 8] = b"LHSTBLK2";
const CONFIG_LEN: usize = 36;
/// Empty-store sentinel for `highest_written_slot` in the per-file config.
const EMPTY_SLOT: u64 = u64::MAX;
/// e2store version record, written once at the start of each data file.
const VERSION_RECORD: [u8; 8] = [0x65, 0x32, 0, 0, 0, 0, 0, 0];

const COMPRESSION_NONE: u8 = 0;
const COMPRESSION_SNAPPY: u8 = 1;

/// On-disk format settings for one `StaticFile`. On first creation the build's
/// values are persisted; on re-open the persisted values win, with
/// `max_value_bytes` ratcheted upward if the build allows larger records.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// e2store record type tag.
    pub record_type: [u8; 2],
    /// Whether values are snappy-framed before write.
    pub compression: bool,
    /// Upper bound on a single decoded record's size in bytes.
    pub max_value_bytes: u64,
}

struct ConfigOnDisk {
    highest_written_slot: Option<u64>,
    current_data_len: u64,
    record_type: [u8; 2],
    compression: bool,
    max_value_bytes: u64,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Compression(io::Error),
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "static file io error: {e}"),
            Self::Compression(e) => write!(f, "static file compression error: {e}"),
            Self::Invalid(message) => write!(f, "static file invalid data: {message}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) | Self::Compression(e) => Some(e),
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
    highest_written_slot: Mutex<Option<u64>>,
}

impl StaticFile {
    /// Open or create a `StaticFile` rooted at `root_dir`. On first creation,
    /// `defaults` is persisted; on re-open, the persisted values win for
    /// `record_type` and `compression`, and `max_value_bytes` is ratcheted up
    /// to `max(on_disk, defaults)`.
    pub fn open(root_dir: PathBuf, defaults: Config) -> Result<Self> {
        fs::create_dir_all(&root_dir)?;

        // First-open: persist current-build defaults. Re-open: persisted
        // settings win over `defaults`, which preserves on-disk readability
        // even if the build's defaults change later.
        let config_path = root_dir.join(CONFIG_FILE);
        let tmp_path = root_dir.join(CONFIG_TMP_FILE);
        if !config_path.exists() {
            atomic_write_config(&config_path, &tmp_path, &root_dir, None, 0, &defaults)?;
        }

        let on_disk = read_config(&config_path)?;
        // record_type and compression are sticky — they're load-bearing for
        // reading old records, so on-disk wins over build-time defaults.
        // max_value_bytes is a soft bound used to cap accepted record sizes;
        // ratchet it up if the build's default is larger so a newer build
        // can write bigger records than an older one persisted, then
        // re-persist immediately so future opens see the new bound.
        let max_value_bytes = on_disk.max_value_bytes.max(defaults.max_value_bytes);
        let config = Config {
            record_type: on_disk.record_type,
            compression: on_disk.compression,
            max_value_bytes,
        };
        if max_value_bytes != on_disk.max_value_bytes {
            atomic_write_config(
                &config_path,
                &tmp_path,
                &root_dir,
                on_disk.highest_written_slot,
                on_disk.current_data_len,
                &config,
            )?;
        }

        let handle = Self {
            root_dir,
            config,
            highest_written_slot: Mutex::new(None),
        };

        if let Some(slot) = on_disk.highest_written_slot {
            handle.heal_current_file(slot, on_disk.current_data_len)?;
        }
        *handle.highest_written_slot.lock() = on_disk.highest_written_slot;

        Ok(handle)
    }

    /// Slot of the most recently committed record, if any.
    pub fn highest_written_slot(&self) -> Option<u64> {
        *self.highest_written_slot.lock()
    }

    /// Read the record at `slot`, if present.
    pub fn get(&self, slot: u64) -> Result<Option<Vec<u8>>> {
        let Some(highest_written_slot) = *self.highest_written_slot.lock() else {
            return Ok(None);
        };
        if slot > highest_written_slot {
            return Ok(None);
        }
        self.read_record(slot)
    }

    /// `true` if a record exists at `slot`. Cheaper than `get` — only the
    /// `.off` sidecar is consulted; the data file is not read.
    pub fn contains(&self, slot: u64) -> Result<bool> {
        let Some(highest_written_slot) = *self.highest_written_slot.lock() else {
            return Ok(false);
        };
        if slot > highest_written_slot {
            return Ok(false);
        }
        Ok(self.read_offset(file_id(slot), slot)? != 0)
    }

    /// Durably store `bytes` at `slot`. Slots must arrive strictly ascending,
    /// or be an identical-value re-put of a previously committed slot
    /// (re-puts at any committed slot are idempotent so migration retries
    /// after a mid-loop crash are safe). A previously-skipped slot (offset
    /// zero) cannot be filled — that would break the append-only data file.
    pub fn put(&self, slot: u64, bytes: &[u8]) -> Result<()> {
        let mut highest_written_slot = self.highest_written_slot.lock();
        if let Some(highest) = *highest_written_slot
            && slot <= highest
        {
            let existing = self.read_record(slot)?.ok_or_else(|| {
                Error::Invalid(format!(
                    "re-put at slot {slot} <= highest {highest} but no record exists; \
                     cannot fill a previously-skipped slot"
                ))
            })?;
            if existing == bytes {
                return Ok(());
            }
            return Err(Error::Invalid(format!(
                "re-put at slot {slot} with mismatched value"
            )));
        }

        let payload = if self.config.compression {
            compress_record(bytes)?
        } else {
            bytes.to_vec()
        };
        let payload_len =
            u32::try_from(payload.len()).map_err(|_| Error::Invalid("record too large".into()))?;

        let target_file_id = file_id(slot);
        // Discard an uncommitted next-file tail after a crash.
        let reset_file = (*highest_written_slot).map(file_id) != Some(target_file_id);
        let off_pos = offset_position(slot);
        let data_path = self.data_path(target_file_id);
        let off_path = self.offset_path(target_file_id);

        let mut data_file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&data_path)?;
        if reset_file {
            data_file.set_len(0)?;
        }

        if data_file.metadata()?.len() == 0 {
            data_file.write_all(&VERSION_RECORD)?;
        }

        let offset = data_file.seek(SeekFrom::End(0))?;
        write_record(
            &mut data_file,
            self.config.record_type,
            payload_len,
            &payload,
        )?;
        let data_len = data_file.seek(SeekFrom::End(0))?;
        // Data and offset files must hit disk before the config commit marker.
        data_file.sync_all()?;

        let mut off_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&off_path)?;
        if reset_file {
            off_file.set_len(0)?;
        }
        if off_file.metadata()?.len() < OFFSET_FILE_LEN {
            off_file.set_len(OFFSET_FILE_LEN)?;
        }
        off_file.seek(SeekFrom::Start(off_pos))?;
        off_file.write_all(&offset.to_le_bytes())?;
        off_file.sync_all()?;

        // Atomic config update is the commit point.
        self.write_config(Some(slot), data_len)?;
        *highest_written_slot = Some(slot);

        Ok(())
    }

    /// Append `items` with one fsync per file (data + offset), not per slot.
    /// Whole batch is durable on return — the same caller-visible contract as
    /// `put` — but with O(1) syncs per underlying file instead of O(n) per
    /// item.
    ///
    /// Walks `items` once, grouping them by `file_id`. For each group, opens
    /// the data file and offset file once, appends every record's bytes
    /// (collecting `(slot, offset)` pairs in memory), writes the offset
    /// table, fsyncs both files, then commits via `write_config`. Idempotent
    /// re-put of `items[0]` at `highest_written_slot` is honored as in `put`.
    pub fn put_batch(&self, items: Vec<(u64, Vec<u8>)>) -> Result<()> {
        if items.is_empty() {
            return Ok(());
        }

        // Validate ascending order up front (cheap, catches caller bugs).
        for w in items.windows(2) {
            if w[1].0 <= w[0].0 {
                return Err(Error::Invalid(
                    "put_batch slots must be strictly ascending".into(),
                ));
            }
        }

        let mut highest_written_slot = self.highest_written_slot.lock();
        let mut iter = items.into_iter().peekable();

        // Idempotent re-put: if the first item is exactly highest_written_slot
        // with matching bytes, drop it from the batch.
        if let (Some(highest), Some((first_slot, _))) = (*highest_written_slot, iter.peek()) {
            if *first_slot < highest {
                return Err(Error::Invalid(
                    "put_batch out of order vs highest_written_slot".into(),
                ));
            }
            if *first_slot == highest {
                let (slot, value) = iter.next().expect("peeked");
                let existing = self
                    .read_record(slot)?
                    .ok_or_else(|| Error::Invalid("missing record at highest slot".into()))?;
                if existing != value {
                    return Err(Error::Invalid("re-put with mismatched value".into()));
                }
            }
        }

        // Group remaining items by file_id, write each group with a single
        // fsync per file.
        let mut last_slot: Option<u64> = None;
        let mut last_data_len: u64 = 0;
        while iter.peek().is_some() {
            let target_file_id = file_id(iter.peek().expect("peeked").0);
            let mut group: Vec<(u64, Vec<u8>)> = Vec::new();
            while let Some(&(slot, _)) = iter.peek() {
                if file_id(slot) != target_file_id {
                    break;
                }
                group.push(iter.next().expect("peeked"));
            }

            let reset_file = (*highest_written_slot).map(file_id) != Some(target_file_id);
            let data_path = self.data_path(target_file_id);
            let off_path = self.offset_path(target_file_id);

            // Data file: append all records, then fsync once.
            let mut data_file = OpenOptions::new()
                .read(true)
                .append(true)
                .create(true)
                .open(&data_path)?;
            if reset_file {
                data_file.set_len(0)?;
            }
            if data_file.metadata()?.len() == 0 {
                data_file.write_all(&VERSION_RECORD)?;
            }
            // BufWriter coalesces the small-record header writes (8 bytes) and
            // the small payloads into larger syscalls.
            let mut offsets: Vec<(u64, u64)> = Vec::with_capacity(group.len());
            {
                let mut writer = std::io::BufWriter::with_capacity(1 << 20, &mut data_file);
                let mut cursor = writer.get_ref().metadata()?.len();
                for (slot, value) in &group {
                    let payload: std::borrow::Cow<'_, [u8]> = if self.config.compression {
                        compress_record(value)?.into()
                    } else {
                        value.as_slice().into()
                    };
                    let payload_len = u32::try_from(payload.len())
                        .map_err(|_| Error::Invalid("record too large".into()))?;
                    offsets.push((*slot, cursor));
                    // Inline `write_record` to avoid the `&mut File` -> BufWriter mismatch.
                    writer.write_all(&self.config.record_type)?;
                    writer.write_all(&payload_len.to_le_bytes())?;
                    writer.write_all(&0u16.to_le_bytes())?;
                    writer.write_all(&payload)?;
                    cursor += 8 + payload.len() as u64;
                }
                writer.flush()?;
            }
            let data_len = data_file.seek(SeekFrom::End(0))?;
            data_file.sync_all()?;

            // Offset file: open, ensure full size, write all offsets in seek+write
            // pairs (8 bytes each), then fsync once.
            let mut off_file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&off_path)?;
            if reset_file {
                off_file.set_len(0)?;
            }
            if off_file.metadata()?.len() < OFFSET_FILE_LEN {
                off_file.set_len(OFFSET_FILE_LEN)?;
            }
            for (slot, offset) in &offsets {
                off_file.seek(SeekFrom::Start(offset_position(*slot)))?;
                off_file.write_all(&offset.to_le_bytes())?;
            }
            off_file.sync_all()?;

            // Track final slot/data_len for the single config commit at end of batch.
            if let Some((s, _)) = group.last() {
                last_slot = Some(*s);
                last_data_len = data_len;
            }
            *highest_written_slot = last_slot;
        }

        // Single atomic config commit covering the whole batch.
        if let Some(s) = last_slot {
            self.write_config(Some(s), last_data_len)?;
        }

        Ok(())
    }

    /// Read a record at `slot` without consulting the writer mutex. Used by
    /// callers that already hold the lock (`put` for the idempotency check).
    fn read_record(&self, slot: u64) -> Result<Option<Vec<u8>>> {
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
        if header[0..2] != self.config.record_type || header[6..8] != [0, 0] {
            return Err(Error::Invalid("invalid record header".into()));
        }

        let len = u32::from_le_bytes([header[2], header[3], header[4], header[5]]) as usize;
        let mut payload = vec![0; len];
        data_file.read_exact(&mut payload)?;

        if self.config.compression {
            decompress_record(&payload, self.config.max_value_bytes).map(Some)
        } else {
            if (payload.len() as u64) > self.config.max_value_bytes {
                return Err(Error::Invalid("record exceeds size limit".into()));
            }
            Ok(Some(payload))
        }
    }

    fn heal_current_file(&self, slot: u64, current_data_len: u64) -> Result<()> {
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

    fn write_config(&self, highest_written_slot: Option<u64>, current_data_len: u64) -> Result<()> {
        atomic_write_config(
            &self.config_path(),
            &self.root_dir.join(CONFIG_TMP_FILE),
            &self.root_dir,
            highest_written_slot,
            current_data_len,
            &self.config,
        )
    }

    fn read_offset(&self, file_id: u64, slot: u64) -> Result<u64> {
        let off_path = self.offset_path(file_id);
        let mut off_file = File::open(&off_path)?;
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

fn read_config(path: &Path) -> Result<ConfigOnDisk> {
    let bytes = fs::read(path)?;
    if bytes.len() != CONFIG_LEN || &bytes[0..8] != CONFIG_MAGIC {
        return Err(Error::Invalid("invalid config".into()));
    }
    let highest = u64::from_le_bytes(bytes[8..16].try_into().expect("slice length checked"));
    let current_data_len =
        u64::from_le_bytes(bytes[16..24].try_into().expect("slice length checked"));
    let record_type = [bytes[24], bytes[25]];
    let compression = match bytes[26] {
        COMPRESSION_NONE => false,
        COMPRESSION_SNAPPY => true,
        other => {
            return Err(Error::Invalid(format!("unknown compression flag {other}")));
        }
    };
    let max_value_bytes =
        u64::from_le_bytes(bytes[28..36].try_into().expect("slice length checked"));
    Ok(ConfigOnDisk {
        highest_written_slot: (highest != EMPTY_SLOT).then_some(highest),
        current_data_len,
        record_type,
        compression,
        max_value_bytes,
    })
}

fn atomic_write_config(
    config_path: &Path,
    tmp_path: &Path,
    root_dir: &Path,
    highest_written_slot: Option<u64>,
    current_data_len: u64,
    config: &Config,
) -> Result<()> {
    let mut bytes = [0u8; CONFIG_LEN];
    bytes[0..8].copy_from_slice(CONFIG_MAGIC);
    bytes[8..16].copy_from_slice(&highest_written_slot.unwrap_or(EMPTY_SLOT).to_le_bytes());
    bytes[16..24].copy_from_slice(&current_data_len.to_le_bytes());
    bytes[24..26].copy_from_slice(&config.record_type);
    bytes[26] = if config.compression {
        COMPRESSION_SNAPPY
    } else {
        COMPRESSION_NONE
    };
    bytes[27] = 0;
    bytes[28..36].copy_from_slice(&config.max_value_bytes.to_le_bytes());

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

fn compress_record(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = FrameEncoder::new(Vec::new());
    encoder.write_all(bytes).map_err(Error::Compression)?;
    encoder.flush().map_err(Error::Compression)?;
    Ok(encoder.get_ref().clone())
}

fn write_record(
    file: &mut File,
    record_type: [u8; 2],
    payload_len: u32,
    payload: &[u8],
) -> Result<()> {
    file.write_all(&record_type)?;
    file.write_all(&payload_len.to_le_bytes())?;
    file.write_all(&0u16.to_le_bytes())?;
    file.write_all(payload)?;
    Ok(())
}

fn decompress_record(bytes: &[u8], max_value_bytes: u64) -> Result<Vec<u8>> {
    let decoder = FrameDecoder::new(bytes);
    let mut limited = decoder.take(max_value_bytes + 1);
    let mut decompressed = Vec::new();
    limited
        .read_to_end(&mut decompressed)
        .map_err(Error::Compression)?;
    if decompressed.len() as u64 > max_value_bytes {
        return Err(Error::Invalid(
            "record exceeds decompressed size limit".into(),
        ));
    }
    Ok(decompressed)
}

fn sync_dir(path: &Path) -> Result<()> {
    let dir = File::open(path)?;
    dir.sync_all()?;
    Ok(())
}
