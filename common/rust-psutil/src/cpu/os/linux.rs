use std::time::Duration;

use crate::cpu::{CpuTimes, CpuTimesPercent};
use crate::Percent;

pub trait CpuTimesExt {
	/// Time spent waiting for I/O to complete.
	/// This is *not* accounted in idle time counter.
	fn iowait(&self) -> Duration;

	/// Time spent for servicing hardware interrupts.
	fn irq(&self) -> Duration;

	/// Time spent for servicing software interrupts.
	fn softirq(&self) -> Duration;

	/// Time spent by other operating systems running in a virtualized environment.
	fn steal(&self) -> Option<Duration>;

	/// Time spent running a virtual CPU for guest operating systems
	/// under the control of the Linux kernel.
	fn guest(&self) -> Option<Duration>;

	/// Time spent running a niced guest
	/// (virtual CPU for guest operating systems
	/// under the control of the Linux kernel).
	fn guest_nice(&self) -> Option<Duration>;
}

impl CpuTimesExt for CpuTimes {
	fn iowait(&self) -> Duration {
		self.iowait
	}

	fn irq(&self) -> Duration {
		self.irq
	}

	fn softirq(&self) -> Duration {
		self.softirq
	}

	fn steal(&self) -> Option<Duration> {
		self.steal
	}

	fn guest(&self) -> Option<Duration> {
		self.guest
	}

	fn guest_nice(&self) -> Option<Duration> {
		self.guest_nice
	}
}

pub trait CpuTimesPercentExt {
	/// Time spent waiting for I/O to complete.
	/// This is *not* accounted in idle time counter.
	fn iowait(&self) -> Percent;

	/// Time spent for servicing hardware interrupts.
	fn irq(&self) -> Percent;

	/// Time spent for servicing software interrupts.
	fn softirq(&self) -> Percent;

	/// Time spent by other operating systems running in a virtualized environment.
	fn steal(&self) -> Option<Percent>;

	/// Time spent running a virtual CPU for guest operating systems
	/// under the control of the Linux kernel.
	fn guest(&self) -> Option<Percent>;

	/// Time spent running a niced guest
	/// (virtual CPU for guest operating systems
	/// under the control of the Linux kernel).
	fn guest_nice(&self) -> Option<Percent>;
}

impl CpuTimesPercentExt for CpuTimesPercent {
	fn iowait(&self) -> Percent {
		self.iowait
	}

	fn irq(&self) -> Percent {
		self.irq
	}

	fn softirq(&self) -> Percent {
		self.softirq
	}

	fn steal(&self) -> Option<Percent> {
		self.steal
	}

	fn guest(&self) -> Option<Percent> {
		self.guest
	}

	fn guest_nice(&self) -> Option<Percent> {
		self.guest_nice
	}
}
