use crate::memory::VirtualMemory;
use crate::Bytes;

pub trait VirtualMemoryExt {
	fn buffers(&self) -> Bytes;

	fn cached(&self) -> Bytes;

	fn shared(&self) -> Bytes;

	fn wired(&self) -> Bytes;
}

impl VirtualMemoryExt for VirtualMemory {
	fn buffers(&self) -> Bytes {
		todo!()
	}

	fn cached(&self) -> Bytes {
		todo!()
	}

	fn shared(&self) -> Bytes {
		todo!()
	}

	fn wired(&self) -> Bytes {
		todo!()
	}
}
