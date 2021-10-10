use std::path::PathBuf;
use std::string::ToString;
use std::time::Instant;

use crate::common::NetConnectionType;
use crate::process::os::linux::{procfs_stat, ProcessExt as _};
use crate::process::{
	pids, psutil_error_to_process_error, MemType, MemoryInfo, OpenFile, Process, ProcessCpuTimes,
	ProcessResult, Status,
};
use crate::{read_dir, read_file, read_link, Count, Percent, Pid, Result};

/// Returns a path to a file in `/proc/[pid]/`.
pub(crate) fn procfs_path(pid: Pid, name: &str) -> PathBuf {
	PathBuf::from("/proc").join(pid.to_string()).join(&name)
}

impl Process {
	pub(crate) fn sys_new(pid: Pid) -> ProcessResult<Process> {
		let procfs_stat = procfs_stat(pid)?;

		let create_time = procfs_stat.starttime;
		let busy = ProcessCpuTimes::from(&procfs_stat).busy();
		let instant = Instant::now();

		Ok(Process {
			pid,
			create_time,
			busy,
			instant,
			procfs_stat,
		})
	}

	pub(crate) fn procfs_path(&self, name: &str) -> PathBuf {
		procfs_path(self.pid, name)
	}

	pub(crate) fn sys_ppid(&self) -> ProcessResult<Option<Pid>> {
		Ok(self.procfs_stat()?.ppid)
	}

	pub(crate) fn sys_name(&self) -> ProcessResult<String> {
		Ok(self.procfs_stat()?.comm)
	}

	pub(crate) fn sys_exe(&self) -> ProcessResult<PathBuf> {
		read_link(self.procfs_path("exe")).map_err(|e| psutil_error_to_process_error(e, self.pid))
	}

	pub(crate) fn sys_cmdline(&self) -> ProcessResult<Option<String>> {
		Ok(self.cmdline_vec()?.map(|c| c.join(" ")))
	}

	pub(crate) fn sys_cmdline_vec(&self) -> ProcessResult<Option<Vec<String>>> {
		let cmdline = read_file(&self.procfs_path("cmdline"))
			.map_err(|e| psutil_error_to_process_error(e, self.pid))?;

		if cmdline.is_empty() {
			return Ok(None);
		}

		let split = cmdline
			.split_terminator('\0')
			.map(|x| x.to_string())
			.collect();

		Ok(Some(split))
	}

	pub(crate) fn sys_parents(&self) -> Option<Vec<Process>> {
		todo!()
	}

	pub(crate) fn sys_status(&self) -> ProcessResult<Status> {
		Ok(self.procfs_stat()?.state)
	}

	pub(crate) fn sys_cwd(&self) -> ProcessResult<PathBuf> {
		read_link(self.procfs_path("cwd")).map_err(|e| psutil_error_to_process_error(e, self.pid))
	}

	pub(crate) fn sys_username(&self) -> String {
		todo!()
	}

	pub(crate) fn sys_get_nice(&self) -> i32 {
		todo!()
	}

	pub(crate) fn sys_set_nice(&self, _nice: i32) {
		todo!()
	}

	pub(crate) fn sys_num_ctx_switches(&self) -> Count {
		todo!()
	}

	pub(crate) fn sys_num_threads(&self) -> Count {
		todo!()
	}

	pub(crate) fn sys_threads(&self) {
		todo!()
	}

	pub(crate) fn sys_cpu_times(&self) -> ProcessResult<ProcessCpuTimes> {
		Ok(ProcessCpuTimes::from(&self.procfs_stat()?))
	}

	pub(crate) fn sys_memory_info(&self) -> ProcessResult<MemoryInfo> {
		Ok(self.procfs_statm()?.into())
	}

	pub(crate) fn sys_memory_full_info(&self) {
		todo!()
	}

	pub(crate) fn sys_memory_percent_with_type(&self, _type: MemType) -> ProcessResult<Percent> {
		todo!()
	}

	pub(crate) fn sys_children(&self) {
		todo!()
	}

	pub(crate) fn sys_open_files(&self) -> ProcessResult<Vec<OpenFile>> {
		read_dir(self.procfs_path("fd"))
			.map_err(|e| psutil_error_to_process_error(e, self.pid))?
			.into_iter()
			.filter_map(|entry| {
				let path = entry.path();

				let fd = path
					.file_name()
					.expect("directory entries should always contain a file name")
					.to_string_lossy()
					.parse::<u32>()
					.ok()?;
				let open_file = match read_link(&path) {
					Ok(path) => path,
					Err(e) => return Some(Err(psutil_error_to_process_error(e, self.pid))),
				};

				Some(Ok(OpenFile {
					fd: Some(fd),
					path: open_file,
				}))
			})
			.collect()
	}

	pub(crate) fn sys_connections(&self) {
		todo!()
	}

	pub(crate) fn sys_connections_with_type(&self, _type: NetConnectionType) {
		todo!()
	}

	pub(crate) fn sys_wait(&self) {
		todo!()
	}
}

pub fn processes() -> Result<Vec<ProcessResult<Process>>> {
	let processes = pids()?.into_iter().map(Process::new).collect();

	Ok(processes)
}
