use std::collections::HashMap;

use crate::process::os::linux::{
	procfs_stat, procfs_statm, procfs_status, ProcfsStat, ProcfsStatm, ProcfsStatus,
};
use crate::process::{psutil_error_to_process_error, Process, ProcessResult};
use crate::{read_file, Error, Result};

fn parse_environ(contents: &str) -> Result<HashMap<String, String>> {
	contents
		.split_terminator('\0')
		.map(|mapping| {
			let split = match mapping.splitn(2, '=').collect::<Vec<_>>() {
				split if split.len() == 2 => Ok(split),
				_ => Err(Error::MissingData {
					path: "environ".into(),
					contents: contents.to_string(),
				}),
			}?;

			Ok((split[0].to_owned(), split[1].to_owned()))
		})
		.collect()
}

pub struct IoCounters {}

pub trait ProcessExt {
	fn environ(&self) -> ProcessResult<HashMap<String, String>>;

	fn get_ionice(&self) -> i32;

	fn set_ionice(&self, nice: i32);

	fn get_rlimit(&self) -> i32;

	fn set_rlimit(&self, nice: i32);

	fn io_counters(&self) -> IoCounters;

	fn get_cpu_affinity(&self) -> i32;

	fn set_cpu_affinity(&self, nice: i32);

	fn cpu_num(&self) -> i32;

	fn memory_maps(&self);

	/// New method, not in Python psutil
	fn procfs_stat(&self) -> ProcessResult<ProcfsStat>;

	/// New method, not in Python psutil
	fn procfs_statm(&self) -> ProcessResult<ProcfsStatm>;

	/// New method, not in Python psutil
	fn procfs_status(&self) -> ProcessResult<ProcfsStatus>;
}

impl ProcessExt for Process {
	fn environ(&self) -> ProcessResult<HashMap<String, String>> {
		let contents = read_file(self.procfs_path("environ"))
			.map_err(|e| psutil_error_to_process_error(e, self.pid))?;

		parse_environ(&contents).map_err(|e| psutil_error_to_process_error(e, self.pid))
	}

	fn get_ionice(&self) -> i32 {
		todo!()
	}

	fn set_ionice(&self, _nice: i32) {
		todo!()
	}

	fn get_rlimit(&self) -> i32 {
		todo!()
	}

	fn set_rlimit(&self, _nice: i32) {
		todo!()
	}

	fn io_counters(&self) -> IoCounters {
		todo!()
	}

	fn get_cpu_affinity(&self) -> i32 {
		todo!()
	}

	fn set_cpu_affinity(&self, _nice: i32) {
		todo!()
	}

	fn cpu_num(&self) -> i32 {
		todo!()
	}

	fn memory_maps(&self) {
		todo!()
	}

	fn procfs_stat(&self) -> ProcessResult<ProcfsStat> {
		procfs_stat(self.pid)
	}

	fn procfs_statm(&self) -> ProcessResult<ProcfsStatm> {
		procfs_statm(self.pid)
	}

	fn procfs_status(&self) -> ProcessResult<ProcfsStatus> {
		procfs_status(self.pid)
	}
}

#[cfg(test)]
mod unit_tests {
	use super::*;

	#[test]
	fn test_parse_environ() {
		let data = "HOME=/\0init=/sbin/init\0recovery=\0TERM=linux\0BOOT_IMAGE=/boot/vmlinuz-3.13.0-128-generic\0PATH=/sbin:/usr/sbin:/bin:/usr/bin\0PWD=/\0rootmnt=/root\0";
		let env = parse_environ(data).unwrap();
		assert_eq!(env["HOME"], "/");
		assert_eq!(env["rootmnt"], "/root");
		assert_eq!(env["recovery"], "");
	}
}
