#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use std::ops::Sub;
use std::time::Duration;

/// Every attribute represents the seconds the CPU has spent in the given mode.
#[cfg_attr(feature = "serde", serde(crate = "renamed_serde"))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuTimes {
	pub(crate) user: Duration,
	pub(crate) system: Duration,
	pub(crate) idle: Duration,
	pub(crate) nice: Duration,

	#[cfg(target_os = "linux")]
	pub(crate) iowait: Duration,
	#[cfg(target_os = "linux")]
	pub(crate) irq: Duration,
	#[cfg(target_os = "linux")]
	pub(crate) softirq: Duration,
	#[cfg(target_os = "linux")]
	pub(crate) steal: Option<Duration>,
	#[cfg(target_os = "linux")]
	pub(crate) guest: Option<Duration>,
	#[cfg(target_os = "linux")]
	pub(crate) guest_nice: Option<Duration>,
}

impl CpuTimes {
	/// Time spent by normal processes executing in user mode;
	/// on Linux this also includes guest time.
	pub fn user(&self) -> Duration {
		self.user
	}

	/// Time spent by processes executing in kernel mode.
	pub fn system(&self) -> Duration {
		self.system
	}

	/// Time spent doing nothing.
	pub fn idle(&self) -> Duration {
		#[cfg(target_os = "linux")]
		{
			self.idle + self.iowait
		}
		#[cfg(target_os = "macos")]
		{
			self.idle
		}
		#[cfg(not(any(target_os = "linux", target_os = "macos")))]
		{
			todo!()
		}
	}

	/// New method, not in Python psutil.
	pub fn busy(&self) -> Duration {
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
		#[cfg(not(any(target_os = "linux", target_os = "macos")))]
		{
			todo!()
		}
	}

	/// New method, not in Python psutil.
	pub fn total(&self) -> Duration {
		self.busy() + self.idle()
	}
}

impl Sub for &CpuTimes {
	type Output = CpuTimes;

	fn sub(self, other: Self) -> Self::Output {
		CpuTimes {
			// have to use `checked_sub` since CPU times can decrease over time on some platforms
			// https://github.com/giampaolo/psutil/blob/e65cc95de72828caed74c7916530dd74fca351e3/psutil/__init__.py#L1687
			user: self.user.checked_sub(other.user).unwrap_or_default(),
			system: self.system.checked_sub(other.system).unwrap_or_default(),
			idle: self.idle.checked_sub(other.idle).unwrap_or_default(),
			nice: self.nice.checked_sub(other.nice).unwrap_or_default(),

			#[cfg(target_os = "linux")]
			iowait: self.iowait.checked_sub(other.iowait).unwrap_or_default(),
			#[cfg(target_os = "linux")]
			irq: self.irq.checked_sub(other.irq).unwrap_or_default(),
			#[cfg(target_os = "linux")]
			softirq: self.softirq.checked_sub(other.softirq).unwrap_or_default(),
			#[cfg(target_os = "linux")]
			steal: self.steal.and_then(|first| {
				other
					.steal
					.map(|second| first.checked_sub(second).unwrap_or_default())
			}),
			#[cfg(target_os = "linux")]
			guest: self.guest.and_then(|first| {
				other
					.guest
					.map(|second| first.checked_sub(second).unwrap_or_default())
			}),
			#[cfg(target_os = "linux")]
			guest_nice: self.guest_nice.and_then(|first| {
				other
					.guest_nice
					.map(|second| first.checked_sub(second).unwrap_or_default())
			}),
		}
	}
}
