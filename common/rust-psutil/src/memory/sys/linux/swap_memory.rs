use crate::memory::{make_map, SwapMemory};
use crate::utils::u64_percent;
use crate::{read_file, Error, Result};

const PROC_MEMINFO: &str = "/proc/meminfo";
const PROC_VMSTAT: &str = "/proc/vmstat";

// TODO: return an option for when swap is disabled?
pub fn swap_memory() -> Result<SwapMemory> {
	let meminfo_contents = read_file(PROC_MEMINFO)?;
	let meminfo = make_map(&meminfo_contents, PROC_MEMINFO)?;

	let vmstat_contents = read_file(PROC_VMSTAT)?;
	let vmstat = make_map(&vmstat_contents, PROC_VMSTAT)?;

	let meminfo_get = |key: &str| -> Result<u64> {
		meminfo.get(key).copied().ok_or(Error::MissingData {
			path: PROC_MEMINFO.into(),
			contents: meminfo_contents.clone(),
		})
	};
	let vmstat_get = |key: &str| -> Result<u64> {
		vmstat.get(key).copied().ok_or(Error::MissingData {
			path: PROC_VMSTAT.into(),
			contents: vmstat_contents.clone(),
		})
	};

	let total = meminfo_get("SwapTotal")?;
	let free = meminfo_get("SwapFree")?;

	let swapped_in = vmstat_get("pswpin")?;
	let swapped_out = vmstat_get("pswpout")?;

	let used = total - free;
	// total will be 0 if swap is disabled
	let percent = if total == 0 {
		0.0
	} else {
		u64_percent(used, total)
	};

	Ok(SwapMemory {
		total,
		used,
		free,
		percent,
		swapped_in,
		swapped_out,
	})
}
