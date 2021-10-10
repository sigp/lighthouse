// #[cfg(feature = "serde")]
// use serde::{Deserialize, Serialize};

use std::cmp;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use nix::sys::signal::{kill, Signal};
use nix::unistd;

use crate::common::NetConnectionType;
use crate::memory;
use crate::process::{
	psutil_error_to_process_error, MemType, MemoryInfo, OpenFile, ProcessCpuTimes, ProcessError,
	ProcessResult, Status,
};
use crate::utils::duration_percent;
use crate::{Count, Percent, Pid};

#[cfg(target_os = "linux")]
use crate::process::os::linux::ProcfsStat;

// #[cfg_attr(feature = "serde", serde(crate = "renamed_serde"))]
// #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct Process {
	pub(crate) pid: Pid,
	pub(crate) create_time: Duration,
	pub(crate) busy: Duration,
	// FIXME: Instant does not serialize/deserialize, cannot add serde
	// #[cfg_attr(feature = "serde", serde(skip))]
	pub(crate) instant: Instant,

	#[cfg(target_os = "linux")]
	// TODO: ignore debug for this field when the feature becomes available.
	// https://github.com/rust-lang/rust/issues/37009
	pub(crate) procfs_stat: ProcfsStat,
}

impl Process {
	pub fn new(pid: Pid) -> ProcessResult<Process> {
		Process::sys_new(pid)
	}

	pub fn current() -> ProcessResult<Process> {
		Process::new(std::process::id())
	}

	pub fn pid(&self) -> Pid {
		self.pid
	}

	pub fn ppid(&self) -> ProcessResult<Option<Pid>> {
		self.sys_ppid()
	}

	pub fn name(&self) -> ProcessResult<String> {
		self.sys_name()
	}

	pub fn exe(&self) -> ProcessResult<PathBuf> {
		self.sys_exe()
	}

	/// On Linux, an `Ok(None)` is usually due to the process being a kernel thread.
	/// The return value is different from Python psutil.
	pub fn cmdline(&self) -> ProcessResult<Option<String>> {
		self.sys_cmdline()
	}

	/// New method, not in Python psutil.
	/// On Linux, an `Ok(None)` is usually due to the process being a kernel thread.
	pub fn cmdline_vec(&self) -> ProcessResult<Option<Vec<String>>> {
		self.sys_cmdline_vec()
	}

	/// The process creation time as a `Duration` since the boot time.
	/// The return value is different from Python psutil.
	pub fn create_time(&self) -> Duration {
		self.create_time
	}

	/// Preemptively checks if the process is still alive.
	pub fn parent(&self) -> ProcessResult<Option<Process>> {
		if !self.is_running() {
			return Err(ProcessError::NoSuchProcess { pid: self.pid });
		}

		self.ppid()?.map(Process::new).transpose()
	}

	pub fn parents(&self) -> Option<Vec<Process>> {
		self.sys_parents()
	}

	pub fn status(&self) -> ProcessResult<Status> {
		self.sys_status()
	}

	pub fn cwd(&self) -> ProcessResult<PathBuf> {
		self.sys_cwd()
	}

	pub fn username(&self) -> String {
		self.sys_username()
	}

	pub fn get_nice(&self) -> i32 {
		self.sys_get_nice()
	}

	pub fn set_nice(&self, nice: i32) {
		self.sys_set_nice(nice)
	}

	pub fn num_ctx_switches(&self) -> Count {
		self.sys_num_ctx_switches()
	}

	pub fn num_threads(&self) -> Count {
		self.sys_num_threads()
	}

	pub fn threads(&self) {
		self.sys_threads()
	}

	pub fn cpu_times(&self) -> ProcessResult<ProcessCpuTimes> {
		self.sys_cpu_times()
	}

	/// Returns the cpu percent since the process was created, replaced, or since the last time this
	/// method was called.
	/// Differs from Python psutil since there is no interval argument.
	pub fn cpu_percent(&mut self) -> ProcessResult<Percent> {
		let busy = self.cpu_times()?.busy();
		let instant = Instant::now();

		let percent = duration_percent(
			// have to use checked_sub since CPU times can decrease over time at least on Linux
			// https://github.com/cjbassi/ytop/issues/34
			// TODO: figure out why. hibernation? something to do with running VMs?
			busy.checked_sub(self.busy).unwrap_or_default(),
			// TODO: can duration be zero if cpu_percent is called consecutively without allowing
			// 		enough time to pass? Cause then we have division by zero.
			instant - self.instant,
		);

		self.busy = busy;
		self.instant = instant;

		Ok(percent)
	}

	pub fn memory_info(&self) -> ProcessResult<MemoryInfo> {
		self.sys_memory_info()
	}

	pub fn memory_full_info(&self) {
		self.sys_memory_full_info()
	}

	pub fn memory_percent(&self) -> ProcessResult<Percent> {
		let virtual_memory =
			memory::virtual_memory().map_err(|e| psutil_error_to_process_error(e, self.pid))?;

		self.memory_percent_oneshot(&virtual_memory)
	}

	pub fn memory_percent_oneshot(
		&self,
		virtual_memory: &memory::VirtualMemory,
	) -> ProcessResult<Percent> {
		let memory_info = self.memory_info()?;
		let percent = (memory_info.rss() as f64 / virtual_memory.total() as f64) * 100.0;

		Ok(percent as f32)
	}

	pub fn memory_percent_with_type(&self, r#type: MemType) -> ProcessResult<Percent> {
		self.sys_memory_percent_with_type(r#type)
	}

	pub fn children(&self) {
		self.sys_children()
	}

	pub fn open_files(&self) -> ProcessResult<Vec<OpenFile>> {
		self.sys_open_files()
	}

	pub fn connections(&self) {
		self.sys_connections()
	}

	pub fn connections_with_type(&self, type_: NetConnectionType) {
		self.sys_connections_with_type(type_)
	}

	pub fn is_running(&self) -> bool {
		match Process::new(self.pid) {
			Ok(p) => p == *self,
			Err(_) => false,
		}
	}

	/// New method, not in Python psutil.
	pub fn is_replaced(&self) -> bool {
		match Process::new(self.pid) {
			Ok(p) => p != *self,
			Err(_) => false,
		}
	}

	/// New method, not in Python psutil.
	pub fn replace(&mut self) -> bool {
		match Process::new(self.pid) {
			Ok(p) if p != *self => {
				*self = p;
				true
			}
			_ => false,
		}
	}

	/// Preemptively checks if the process is still alive.
	pub fn send_signal(&self, signal: Signal) -> ProcessResult<()> {
		if !self.is_running() {
			return Err(ProcessError::NoSuchProcess { pid: self.pid });
		}

		#[cfg(target_family = "unix")]
		{
			kill(unistd::Pid::from_raw(self.pid as i32), signal)
				.map_err(From::from)
				.map_err(|e| psutil_error_to_process_error(e, self.pid))
		}
		#[cfg(not(any(target_family = "unix")))]
		{
			// e.g. windows only supports relatively few signals.
			// https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/signal?view=vs-2019
			todo!()
		}
	}

	/// Preemptively checks if the process is still alive.
	pub fn suspend(&self) -> ProcessResult<()> {
		#[cfg(target_family = "unix")]
		{
			self.send_signal(Signal::SIGSTOP)
		}
		#[cfg(not(any(target_family = "unix")))]
		{
			todo!()
		}
	}

	/// Preemptively checks if the process is still alive.
	pub fn resume(&self) -> ProcessResult<()> {
		#[cfg(target_family = "unix")]
		{
			self.send_signal(Signal::SIGCONT)
		}
		#[cfg(not(any(target_family = "unix")))]
		{
			todo!()
		}
	}

	/// Preemptively checks if the process is still alive.
	pub fn terminate(&self) -> ProcessResult<()> {
		self.send_signal(Signal::SIGTERM)
	}

	/// Preemptively checks if the process is still alive.
	pub fn kill(&self) -> ProcessResult<()> {
		#[cfg(target_family = "unix")]
		{
			self.send_signal(Signal::SIGKILL)
		}
		#[cfg(not(any(target_family = "unix")))]
		{
			todo!()
		}
	}

	pub fn wait(&self) {
		self.sys_wait()
	}
}

impl PartialEq for Process {
	// Compares processes using their pid and create_time as a unique identifier.
	fn eq(&self, other: &Process) -> bool {
		(self.pid() == other.pid()) && (self.create_time() == other.create_time())
	}
}

impl cmp::Eq for Process {}

impl Hash for Process {
	fn hash<H: Hasher>(&self, state: &mut H) {
		self.pid().hash(state);
		self.create_time().hash(state);
	}
}

#[cfg(test)]
mod unit_tests {
	use super::*;
	use crate::process::processes;

	#[test]
	fn test_process_exe() {
		assert!(Process::current().unwrap().exe().is_ok());
	}

	#[test]
	fn test_process_cmdline() {
		assert!(Process::current().unwrap().cmdline().is_ok());
	}

	#[test]
	fn test_process_cwd() {
		assert!(Process::current().unwrap().cwd().is_ok());
	}

	#[test]
	fn test_process_equality() {
		assert_eq!(Process::current().unwrap(), Process::current().unwrap());
	}

	/// This could fail if you run the tests as PID 1. Please don't do that.
	#[test]
	fn test_process_inequality() {
		assert_ne!(Process::current().unwrap(), Process::new(1).unwrap());
	}

	#[test]
	fn test_processes() {
		processes().unwrap();
	}
}
