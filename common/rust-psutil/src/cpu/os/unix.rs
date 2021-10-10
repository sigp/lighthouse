use std::time::Duration;

use crate::cpu::{CpuTimes, CpuTimesPercent};
use crate::Percent;

pub trait CpuTimesExt {
	/// Time spent by niced (prioritized) processes executing in user mode;
	/// on Linux this also includes guest_nice time.
	fn nice(&self) -> Duration;
}

impl CpuTimesExt for CpuTimes {
	fn nice(&self) -> Duration {
		self.nice
	}
}

pub trait CpuTimesPercentExt {
	/// Time spent by niced (prioritized) processes executing in user mode;
	/// on Linux this also includes guest_nice time.
	fn nice(&self) -> Percent;
}

impl CpuTimesPercentExt for CpuTimesPercent {
	fn nice(&self) -> Percent {
		self.nice
	}
}
