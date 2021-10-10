use crate::process::Process;

pub struct IoCounters {}

pub trait ProcessExt {
	fn io_counters(&self) -> IoCounters;
}

impl ProcessExt for Process {
	fn io_counters(&self) -> IoCounters {
		todo!()
	}
}
