use crate::memory::VirtualMemory;
use crate::Bytes;

pub trait VirtualMemoryExt {
	/// Memory currently in use.
	fn active(&self) -> Bytes;

	/// Memory that is not in use.
	fn inactive(&self) -> Bytes;
}

impl VirtualMemoryExt for VirtualMemory {
	fn active(&self) -> Bytes {
		self.active
	}

	fn inactive(&self) -> Bytes {
		self.inactive
	}
}
