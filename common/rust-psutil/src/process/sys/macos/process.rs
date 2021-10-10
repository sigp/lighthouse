// https://github.com/heim-rs/heim/blob/master/heim-process/src/sys/macos/process/mod.rs
// https://github.com/heim-rs/heim/blob/master/heim-process/src/sys/macos/utils.rs

use std::convert::TryFrom;
use std::ffi::CStr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use nix::libc;

use crate::common::NetConnectionType;
use crate::process::os::macos::{kinfo_proc, kinfo_process, kinfo_processes};
use crate::process::{
	io_error_to_process_error, psutil_error_to_process_error, MemType, MemoryInfo, OpenFile,
	Process, ProcessCpuTimes, ProcessError, ProcessResult, Status,
};
use crate::{Count, Error, Percent, Pid, Result};

fn catch_zombie(proc_err: ProcessError) -> ProcessError {
	if let ProcessError::PsutilError {
		pid,
		source: ref psutil_err,
	} = proc_err
	{
		if let Error::OsError { source: io_err } = psutil_err {
			if io_err.raw_os_error() == Some(libc::ESRCH) {
				let kinfo_proc = match kinfo_process(pid) {
					Ok(info) => info,
					Err(e) => return e,
				};

				return match Status::try_from(kinfo_proc.kp_proc.p_stat) {
					Ok(Status::Zombie) => ProcessError::ZombieProcess { pid },
					Ok(_) => ProcessError::AccessDenied { pid },
					Err(e) => psutil_error_to_process_error(e.into(), pid),
				};
			}
		}
	}

	proc_err
}

fn cpu_times(pid: Pid) -> ProcessResult<ProcessCpuTimes> {
	darwin_libproc::task_info(pid as i32)
		.map(ProcessCpuTimes::from)
		.map_err(|e| catch_zombie(io_error_to_process_error(e, pid)))
}

fn process_id(kinfo_proc: kinfo_proc) -> (Pid, Duration) {
	let pid = kinfo_proc.kp_proc.p_pid as u32;
	let timeval = unsafe {
		// TODO: How can it be guaranteed that in this case
		// `p_un.p_starttime` will be filled correctly?
		kinfo_proc.kp_proc.p_un.p_starttime
	};
	let create_time =
		Duration::from_secs(timeval.tv_sec as u64) + Duration::from_micros(timeval.tv_usec as u64);

	(pid, create_time)
}

fn process_new(kinfo_proc: kinfo_proc) -> ProcessResult<Process> {
	let (pid, create_time) = process_id(kinfo_proc);
	let busy = cpu_times(pid)?.busy();
	let instant = Instant::now();

	Ok(Process {
		pid,
		create_time,
		busy,
		instant,
	})
}

impl Process {
	pub(crate) fn sys_new(pid: Pid) -> ProcessResult<Process> {
		let kinfo_proc = kinfo_process(pid).map_err(catch_zombie)?;

		process_new(kinfo_proc)
	}

	pub(crate) fn sys_ppid(&self) -> ProcessResult<Option<Pid>> {
		todo!()
	}

	pub(crate) fn sys_name(&self) -> ProcessResult<String> {
		kinfo_process(self.pid)
			.map(|kinfo_proc| {
				let raw_str = unsafe { CStr::from_ptr(kinfo_proc.kp_proc.p_comm.as_ptr()) };
				let name = raw_str.to_string_lossy().into_owned();

				name
			})
			.map_err(catch_zombie)
	}

	pub(crate) fn sys_exe(&self) -> ProcessResult<PathBuf> {
		todo!()
	}

	pub(crate) fn sys_cmdline(&self) -> ProcessResult<Option<String>> {
		todo!()
	}

	pub(crate) fn sys_cmdline_vec(&self) -> ProcessResult<Option<Vec<String>>> {
		todo!()
	}

	pub(crate) fn sys_parents(&self) -> Option<Vec<Process>> {
		todo!()
	}

	pub(crate) fn sys_status(&self) -> ProcessResult<Status> {
		todo!()
	}

	pub(crate) fn sys_cwd(&self) -> ProcessResult<PathBuf> {
		todo!()
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
		cpu_times(self.pid)
	}

	pub(crate) fn sys_memory_info(&self) -> ProcessResult<MemoryInfo> {
		darwin_libproc::task_info(self.pid as i32)
			.map(MemoryInfo::from)
			.map_err(|e| catch_zombie(io_error_to_process_error(e, self.pid)))
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
		todo!()
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
	Ok(kinfo_processes()?.into_iter().map(process_new).collect())
}
