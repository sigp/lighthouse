use crate::process::processes;
use crate::{Pid, Result};

pub fn pids() -> Result<Vec<Pid>> {
	Ok(processes()?
		.into_iter()
		.filter_map(|process| process.ok())
		.map(|process| process.pid())
		.collect())
}

pub fn pid_exists(_pid: Pid) -> bool {
	todo!()
}
