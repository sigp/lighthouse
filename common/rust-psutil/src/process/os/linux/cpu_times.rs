use std::time::Duration;

use crate::process::ProcessCpuTimes;

pub trait ProcessCpuTimesExt {
	fn iowait(&self) -> Option<Duration>;
}

impl ProcessCpuTimesExt for ProcessCpuTimes {
	fn iowait(&self) -> Option<Duration> {
		self.iowait
	}
}
