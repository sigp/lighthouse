use std::collections::HashMap;

use crate::disk::DiskIoCounters;
use crate::Result;

pub(crate) fn disk_io_counters_per_partition() -> Result<HashMap<String, DiskIoCounters>> {
	todo!()
}
