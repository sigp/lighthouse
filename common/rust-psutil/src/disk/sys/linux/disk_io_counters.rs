// https://github.com/heim-rs/heim/blob/master/heim-disk/src/sys/linux/counters.rs

use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use crate::disk::DiskIoCounters;
use crate::{read_file, Error, Result};

// Copied from the `psutil` sources:
//
// "man iostat" states that sectors are equivalent with blocks and have
// a size of 512 bytes. Despite this value can be queried at runtime
// via /sys/block/{DISK}/queue/hw_sector_size and results may vary
// between 1k, 2k, or 4k... 512 appears to be a magic constant used
// throughout Linux source code:
// * https://stackoverflow.com/a/38136179/376587
// * https://lists.gt.net/linux/kernel/2241060
// * https://github.com/giampaolo/psutil/issues/1305
// * https://github.com/torvalds/linux/blob/4f671fe2f9523a1ea206f63fe60a7c7b3a56d5c7/include/linux/bio.h#L99
// * https://lkml.org/lkml/2015/8/17/234
const DISK_SECTOR_SIZE: u64 = 512;

const PROC_DISKSTATS: &str = "/proc/diskstats";
const PROC_PARTITIONS: &str = "/proc/partitions";

impl FromStr for DiskIoCounters {
	type Err = Error;

	// At the moment supports format used in Linux 2.6+,
	// except ignoring discard values introduced in Linux 4.18.
	//
	// https://www.kernel.org/doc/Documentation/iostats.txt
	// https://www.kernel.org/doc/Documentation/ABI/testing/procfs-diskstats
	fn from_str(line: &str) -> Result<DiskIoCounters> {
		let fields = match line.split_whitespace().collect::<Vec<_>>() {
			fields if fields.len() >= 14 => Ok(fields),
			_ => Err(Error::MissingData {
				path: PROC_DISKSTATS.into(),
				contents: line.to_string(),
			}),
		}?;

		let parse = |s: &str| -> Result<u64> {
			s.parse().map_err(|err| Error::ParseInt {
				path: PROC_DISKSTATS.into(),
				contents: line.to_string(),
				source: err,
			})
		};

		Ok(DiskIoCounters {
			read_count: parse(fields[3])?,
			write_count: parse(fields[7])?,
			read_bytes: parse(fields[5])? * DISK_SECTOR_SIZE,
			write_bytes: parse(fields[9])? * DISK_SECTOR_SIZE,
			read_time: Duration::from_millis(parse(fields[6])?),
			write_time: Duration::from_millis(parse(fields[10])?),
			busy_time: Duration::from_millis(parse(fields[12])?),
			read_merged_count: parse(fields[4])?,
			write_merged_count: parse(fields[8])?,
		})
	}
}

/// Determine partitions we want to look for.
fn get_partitions(contents: &str) -> Result<Vec<&str>> {
	contents
		.lines()
		.skip(2)
		.map(|line| {
			let fields = match line.split_whitespace().collect::<Vec<_>>() {
				fields if fields.len() >= 4 => Ok(fields),
				_ => Err(Error::MissingData {
					path: PROC_PARTITIONS.into(),
					contents: line.to_string(),
				}),
			}?;

			Ok(fields[3])
		})
		.collect()
}

pub(crate) fn disk_io_counters_per_partition() -> Result<HashMap<String, DiskIoCounters>> {
	let contents = read_file(PROC_PARTITIONS)?;
	let partitions = get_partitions(&contents)?;
	let contents = read_file(PROC_DISKSTATS)?;
	let mut io_counters: HashMap<String, DiskIoCounters> = HashMap::new();

	for line in contents.lines() {
		let fields = match line.split_whitespace().collect::<Vec<_>>() {
			fields if fields.len() >= 14 => Ok(fields),
			_ => Err(Error::MissingData {
				path: PROC_DISKSTATS.into(),
				contents: line.to_string(),
			}),
		}?;

		let name = fields[2];
		if partitions.contains(&name) {
			io_counters.insert(String::from(name), DiskIoCounters::from_str(line)?);
		}
	}

	Ok(io_counters)
}
