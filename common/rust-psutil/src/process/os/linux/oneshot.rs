use std::time::Instant;

use crate::process::{Process, ProcessCpuTimes};
use crate::utils::duration_percent;
use crate::Percent;

pub trait Oneshot {
	fn name_oneshot(&self) -> String;

	fn cpu_times_oneshot(&self) -> ProcessCpuTimes;

	fn cpu_percent_oneshot(&mut self) -> Percent;
}

impl Oneshot for Process {
	fn name_oneshot(&self) -> String {
		self.procfs_stat.comm.to_string()
	}

	fn cpu_times_oneshot(&self) -> ProcessCpuTimes {
		ProcessCpuTimes::from(&self.procfs_stat)
	}

	/// Returns the cpu percent since the process was created, replaced, or since the last time this
	/// method was called.
	/// Differs from Python psutil since there is no interval argument.
	fn cpu_percent_oneshot(&mut self) -> Percent {
		let busy = self.cpu_times_oneshot().busy();
		let instant = Instant::now();

		let percent = duration_percent(
			// have to use checked_sub since CPU times can decrease over time at least on Linux
			// https://github.com/cjbassi/ytop/issues/34
			// TODO: figure out why. hibernation? something to do with running VMs?
			busy.checked_sub(self.busy).unwrap_or_default(),
			// TODO: can duration be zero if cpu_percent is called consecutively without allowing
			// 		enough time to pass? Cause then we have division by zero.
			instant - self.instant,
		);

		self.busy = busy;
		self.instant = instant;

		percent
	}
}
