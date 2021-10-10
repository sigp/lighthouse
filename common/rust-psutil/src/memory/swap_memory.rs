#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{Bytes, Percent};

#[cfg_attr(feature = "serde", serde(crate = "renamed_serde"))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct SwapMemory {
	pub(crate) total: Bytes,
	pub(crate) used: Bytes,
	pub(crate) free: Bytes,
	pub(crate) percent: Percent,
	pub(crate) swapped_in: Bytes,
	pub(crate) swapped_out: Bytes,
}

impl SwapMemory {
	/// Amount of total swap memory.
	pub fn total(&self) -> Bytes {
		self.total
	}

	/// Amount of used swap memory.
	pub fn used(&self) -> Bytes {
		self.used
	}

	/// Amount of free swap memory.
	pub fn free(&self) -> Bytes {
		self.free
	}

	/// Percent of swap memory used.
	pub fn percent(&self) -> Percent {
		self.percent
	}

	/// Amount of memory swapped in from disk.
	/// Renamed from `sin` in Python psutil.
	pub fn swapped_in(&self) -> Bytes {
		self.swapped_in
	}

	/// Amount of memory swapped to disk.
	/// Renamed from `sout` in Python psutil.
	pub fn swapped_out(&self) -> Bytes {
		self.swapped_out
	}
}
