#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{Bytes, Percent};

#[cfg_attr(feature = "serde", serde(crate = "renamed_serde"))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct VirtualMemory {
	pub(crate) total: Bytes,
	pub(crate) available: Bytes,
	pub(crate) used: Bytes,
	pub(crate) free: Bytes,
	pub(crate) percent: Percent,

	#[cfg(target_family = "unix")]
	pub(crate) active: Bytes,
	#[cfg(target_family = "unix")]
	pub(crate) inactive: Bytes,

	#[cfg(target_os = "linux")]
	pub(crate) buffers: Bytes,
	#[cfg(target_os = "linux")]
	pub(crate) cached: Bytes,
	#[cfg(target_os = "linux")]
	pub(crate) shared: Bytes,
	#[cfg(target_os = "linux")]
	pub(crate) slab: Bytes,

	#[cfg(target_os = "macos")]
	pub(crate) wired: Bytes,
}

impl VirtualMemory {
	/// Amount of total memory.
	pub fn total(&self) -> Bytes {
		self.total
	}

	/// Amount of memory available for new processes.
	pub fn available(&self) -> Bytes {
		self.available
	}

	/// Memory currently in use.
	pub fn used(&self) -> Bytes {
		self.used
	}

	/// Memory not being used.
	pub fn free(&self) -> Bytes {
		self.free
	}

	/// New method, not in Python psutil.
	/// Percent of memory used.
	pub fn percent(&self) -> Percent {
		self.percent
	}
}
