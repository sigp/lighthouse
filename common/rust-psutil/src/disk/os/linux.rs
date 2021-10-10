use std::time::Duration;

use crate::disk::DiskIoCounters;
use crate::Count;

pub trait DiskIoCountersExt {
	/// Time spent reading from disk.
	fn read_time(&self) -> Duration;

	/// Time spent writing to disk.
	fn write_time(&self) -> Duration;

	/// Time spent doing actual I/Os.
	fn busy_time(&self) -> Duration;

	/// Number of merged reads.
	fn read_merged_count(&self) -> Count;

	/// Number of merged writes.
	fn write_merged_count(&self) -> Count;
}

impl DiskIoCountersExt for DiskIoCounters {
	fn read_time(&self) -> Duration {
		self.read_time
	}

	fn write_time(&self) -> Duration {
		self.write_time
	}

	fn busy_time(&self) -> Duration {
		self.busy_time
	}

	fn read_merged_count(&self) -> Count {
		self.read_merged_count
	}

	fn write_merged_count(&self) -> Count {
		self.write_merged_count
	}
}
