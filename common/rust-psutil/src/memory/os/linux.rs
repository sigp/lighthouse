use crate::memory::VirtualMemory;
use crate::Bytes;

pub trait VirtualMemoryExt {
	/// Temporary storage for raw disk blocks.
	fn buffers(&self) -> Bytes;

	/// Memory used by the page cache.
	fn cached(&self) -> Bytes;

	/// Amount of memory consumed by tmpfs filesystems.
	fn shared(&self) -> Bytes;

	fn slab(&self) -> Bytes;
}

impl VirtualMemoryExt for VirtualMemory {
	fn buffers(&self) -> Bytes {
		self.buffers
	}

	fn cached(&self) -> Bytes {
		self.cached
	}

	fn shared(&self) -> Bytes {
		self.shared
	}

	fn slab(&self) -> Bytes {
		self.slab
	}
}
