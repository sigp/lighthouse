use crate::memory::{make_map, VirtualMemory};
use crate::{read_file, Error, Result};

const PROC_MEMINFO: &str = "/proc/meminfo";

// TODO: some of this stuff relies on a kernel version greater than 2.6
pub fn virtual_memory() -> Result<VirtualMemory> {
	let contents = read_file(PROC_MEMINFO)?;
	let meminfo = make_map(&contents, PROC_MEMINFO)?;

	let get = |key: &str| -> Result<u64> {
		meminfo.get(key).copied().ok_or(Error::MissingData {
			path: PROC_MEMINFO.into(),
			contents: contents.clone(),
		})
	};

	let total = get("MemTotal")?;
	// since Linux 3.14
	let available = get("MemAvailable")?;
	let free = get("MemFree")?;
	let active = get("Active")?;
	let inactive = get("Inactive")?;
	let buffers = get("Buffers")?;
	// "free" cmdline utility sums reclaimable to cached.
	// Older versions of procps used to add slab memory instead.
	// This got changed in:
	// https://gitlab.com/procps-ng/procps/commit/05d751c4f076a2f0118b914c5e51cfbb4762ad8e
	// SReclaimable available since Linux 2.6.19
	let cached = get("Cached")? + get("SReclaimable")?;
	// since Linux 2.6.32
	let shared = get("Shmem")?;
	let slab = 0; // TODO

	let used = total - free - cached - buffers;
	let percent = (((total as f64 - available as f64) / total as f64) * 100.0) as f32;

	Ok(VirtualMemory {
		total,
		available,
		used,
		free,
		percent,
		active,
		inactive,
		buffers,
		cached,
		shared,
		slab,
	})
}
