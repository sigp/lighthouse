// https://github.com/heim-rs/heim/blob/master/heim-process/src/sys/macos/process/memory.rs
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::Bytes;

#[cfg(target_os = "linux")]
use crate::process::os::linux::ProcfsStatm;
#[cfg(target_os = "macos")]
use crate::Count;

#[cfg_attr(feature = "serde", serde(crate = "renamed_serde"))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum MemType {
	// TODO
}

#[cfg_attr(feature = "serde", serde(crate = "renamed_serde"))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct MemoryInfo {
	pub(crate) rss: Bytes,
	pub(crate) vms: Bytes,

	#[cfg(target_os = "linux")]
	pub(crate) shared: Bytes,
	#[cfg(target_os = "linux")]
	pub(crate) text: Bytes,
	#[cfg(target_os = "linux")]
	pub(crate) data: Bytes,

	#[cfg(target_os = "macos")]
	pub(crate) page_faults: Count,
	#[cfg(target_os = "macos")]
	pub(crate) pageins: Count,
}

impl MemoryInfo {
	pub fn rss(&self) -> Bytes {
		self.rss
	}

	pub fn vms(&self) -> Bytes {
		self.vms
	}
}

#[cfg(target_os = "linux")]
impl From<ProcfsStatm> for MemoryInfo {
	fn from(statm: ProcfsStatm) -> Self {
		MemoryInfo {
			rss: statm.resident,
			vms: statm.size,
			shared: statm.shared,
			text: statm.text,
			data: statm.data,
		}
	}
}

#[cfg(target_os = "macos")]
impl From<darwin_libproc::proc_taskinfo> for MemoryInfo {
	fn from(info: darwin_libproc::proc_taskinfo) -> Self {
		MemoryInfo {
			rss: info.pti_resident_size,
			vms: info.pti_virtual_size,
			page_faults: info.pti_faults as u64,
			pageins: info.pti_pageins as u64,
		}
	}
}
