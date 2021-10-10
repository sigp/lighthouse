use crate::process::Process;

pub trait ProcessExt {
	fn get_cpu_affinity(&self) -> i32;

	fn set_cpu_affinity(&self, nice: i32);

	fn cpu_num(&self);

	fn memory_maps(&self);
}

impl ProcessExt for Process {
	fn get_cpu_affinity(&self) -> i32 {
		todo!()
	}

	fn set_cpu_affinity(&self, _nice: i32) {
		todo!()
	}

	fn cpu_num(&self) {
		todo!()
	}

	fn memory_maps(&self) {
		todo!()
	}
}
