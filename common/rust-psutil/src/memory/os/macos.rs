use crate::memory::VirtualMemory;
use crate::Bytes;

pub trait VirtualMemoryExt {
	fn wired(&self) -> Bytes;
}

impl VirtualMemoryExt for VirtualMemory {
	fn wired(&self) -> Bytes {
		self.wired
	}
}
