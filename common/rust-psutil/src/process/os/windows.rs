use std::collections::HashMap;

use crate::process::{Process, ProcessResult};
use crate::Count;

pub struct IoCounters {}

pub trait ProcessExt {
	fn environ(&self) -> ProcessResult<HashMap<String, String>>;

	fn get_ionice(&self) -> i32;

	fn set_ionice(&self, nice: i32);

	fn io_counters(&self) -> IoCounters;

	fn num_handles(&self) -> Count;

	fn get_cpu_affinity(&self) -> i32;

	fn set_cpu_affinity(&self, nice: i32);

	fn memory_maps(&self);
}

impl ProcessExt for Process {
	fn environ(&self) -> ProcessResult<HashMap<String, String>> {
		todo!()
	}

	fn get_ionice(&self) -> i32 {
		todo!()
	}

	fn set_ionice(&self, _nice: i32) {
		todo!()
	}

	fn io_counters(&self) -> IoCounters {
		todo!()
	}

	fn num_handles(&self) -> Count {
		todo!()
	}

	fn get_cpu_affinity(&self) -> i32 {
		todo!()
	}

	fn set_cpu_affinity(&self, _nice: i32) {
		todo!()
	}

	fn memory_maps(&self) {
		todo!()
	}
}
