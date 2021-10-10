#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use std::time::Duration;

use crate::cpu::{cpu_times, cpu_times_percpu, CpuTimes};
use crate::utils::duration_percent;
use crate::{Percent, Result};

/// Every attribute represents the percentage of time the CPU has spent in the given mode.
#[cfg_attr(feature = "serde", serde(crate = "renamed_serde"))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CpuTimesPercent {
	pub(crate) user: Percent,
	pub(crate) system: Percent,
	pub(crate) idle: Percent,
	pub(crate) nice: Percent,

	#[cfg(target_os = "linux")]
	pub(crate) iowait: Percent,
	#[cfg(target_os = "linux")]
	pub(crate) irq: Percent,
	#[cfg(target_os = "linux")]
	pub(crate) softirq: Percent,
	#[cfg(target_os = "linux")]
	pub(crate) steal: Option<Percent>,
	#[cfg(target_os = "linux")]
	pub(crate) guest: Option<Percent>,
	#[cfg(target_os = "linux")]
	pub(crate) guest_nice: Option<Percent>,
}

impl CpuTimesPercent {
	/// Time spent by normal processes executing in user mode;
	/// on Linux this also includes guest time.
	pub fn user(&self) -> Percent {
		self.user
	}

	/// Time spent by processes executing in kernel mode.
	pub fn system(&self) -> Percent {
		self.system
	}

	/// Time spent doing nothing.
	pub fn idle(&self) -> Percent {
		#[cfg(target_os = "linux")]
		{
			self.idle + self.iowait
		}
		#[cfg(target_os = "macos")]
		{
			self.idle
		}
	}

	/// New method, not in Python psutil.
	pub fn busy(&self) -> Percent {
		#[cfg(target_os = "linux")]
		{
			// On Linux guest times are already accounted in "user" or "nice" times.
			// https://github.com/giampaolo/psutil/blob/e65cc95de72828caed74c7916530dd74fca351e3/psutil/__init__.py#L1653
			self.user
				+ self.system + self.nice
				+ self.irq + self.softirq
				+ self.steal.unwrap_or_default()
		}
		#[cfg(target_os = "macos")]
		{
			self.user + self.system + self.nice
		}
	}
}

impl From<CpuTimes> for CpuTimesPercent {
	fn from(cpu_times: CpuTimes) -> Self {
		let total = cpu_times.total();

		// total can be zero if cpu_times_percent is called consecutively without allowing enough
		// 		time to pass
		// or also when CPU times decrease over time and we reset the calculated value to zero
		if total == Duration::default() {
			return CpuTimesPercent::default();
		}

		let user = duration_percent(cpu_times.user, total);
		let system = duration_percent(cpu_times.system, total);
		let idle = duration_percent(cpu_times.idle, total);
		let nice = duration_percent(cpu_times.nice, total);

		#[cfg(target_os = "linux")]
		let iowait = duration_percent(cpu_times.iowait, total);
		#[cfg(target_os = "linux")]
		let irq = duration_percent(cpu_times.irq, total);
		#[cfg(target_os = "linux")]
		let softirq = duration_percent(cpu_times.softirq, total);

		#[cfg(target_os = "linux")]
		let steal = cpu_times.steal.map(|steal| duration_percent(steal, total));
		#[cfg(target_os = "linux")]
		let guest = cpu_times.guest.map(|guest| duration_percent(guest, total));
		#[cfg(target_os = "linux")]
		let guest_nice = cpu_times
			.guest_nice
			.map(|guest_nice| duration_percent(guest_nice, total));

		CpuTimesPercent {
			user,
			system,
			idle,
			nice,

			#[cfg(target_os = "linux")]
			iowait,
			#[cfg(target_os = "linux")]
			irq,
			#[cfg(target_os = "linux")]
			softirq,
			#[cfg(target_os = "linux")]
			steal,
			#[cfg(target_os = "linux")]
			guest,
			#[cfg(target_os = "linux")]
			guest_nice,
		}
	}
}

/// Get `CpuTimesPercent`s in non-blocking mode.
///
/// Example:
///
/// ```
/// let mut cpu_times_percent_collector = psutil::cpu::CpuTimesPercentCollector::new().unwrap();
///
/// let cpu_times_percent = cpu_times_percent_collector.cpu_times_percent().unwrap();
/// let cpu_times_percent_percpu = cpu_times_percent_collector.cpu_times_percent_percpu().unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct CpuTimesPercentCollector {
	cpu_times: CpuTimes,
	cpu_times_percpu: Vec<CpuTimes>,
}

impl CpuTimesPercentCollector {
	/// Initialize the `CpuTimesPercentCollector` so the method calls are ready to be used.
	pub fn new() -> Result<CpuTimesPercentCollector> {
		let cpu_times = cpu_times()?;
		let cpu_times_percpu = cpu_times_percpu()?;

		Ok(CpuTimesPercentCollector {
			cpu_times,
			cpu_times_percpu,
		})
	}

	/// Returns a `CpuTimesPercent` since the last time this was called or since
	/// `CpuTimesPercentCollector::new()` was called.
	pub fn cpu_times_percent(&mut self) -> Result<CpuTimesPercent> {
		let current_cpu_times = cpu_times()?;
		let cpu_percent_since = CpuTimesPercent::from(&current_cpu_times - &self.cpu_times);
		self.cpu_times = current_cpu_times;

		Ok(cpu_percent_since)
	}

	/// Returns a `CpuTimesPercent` for each cpu since the last time this was called or since
	/// `CpuTimesPercentCollector::new()` was called.
	pub fn cpu_times_percent_percpu(&mut self) -> Result<Vec<CpuTimesPercent>> {
		let current_cpu_times_percpu = cpu_times_percpu()?;
		let vec = self
			.cpu_times_percpu
			.iter()
			.zip(current_cpu_times_percpu.iter())
			.map(|(prev, cur)| CpuTimesPercent::from(cur - prev))
			.collect();
		self.cpu_times_percpu = current_cpu_times_percpu;

		Ok(vec)
	}
}
