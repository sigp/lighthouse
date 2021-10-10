use std::time::Duration;

use crate::disk::DiskIoCounters;

pub trait DiskIoCountersExt {
	fn read_time(&self) -> Duration;

	fn write_time(&self) -> Duration;
}

impl DiskIoCountersExt for DiskIoCounters {
	fn read_time(&self) -> Duration {
		todo!()
	}

	fn write_time(&self) -> Duration {
		todo!()
	}
}
