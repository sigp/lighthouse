#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use std::str::FromStr;
use std::time::Duration;

use crate::process::{procfs_path, psutil_error_to_process_error, ProcessResult, Status};
use crate::{read_file, Error, Pid, Result, PAGE_SIZE, TICKS_PER_SECOND};

const STAT: &str = "stat";

/// New struct, not in Python psutil.
#[cfg_attr(feature = "serde", serde(crate = "renamed_serde"))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct ProcfsStat {
	/// PID of the process.
	pub pid: Pid,

	/// Filename of the executable.
	pub comm: String,

	/// State of the process as an enum.
	pub state: Status,

	/// PID of the parent process.
	pub ppid: Option<Pid>,

	/// Process group ID.
	pub pgrp: i32,

	/// Session ID.
	pub session: i32,

	/// Controlling terminal of the process [TODO: Actually two numbers].
	pub tty_nr: i32,

	/// ID of the foreground group of the controlling terminal.
	pub tpgid: i32,

	/// Kernel flags for the process.
	pub flags: u32,

	/// Minor faults.
	pub minflt: u64,

	/// Minor faults by child processes.
	pub cminflt: u64,

	/// Major faults.
	pub majflt: u64,

	/// Major faults by child processes.
	pub cmajflt: u64,

	/// Time scheduled in user mode (seconds).
	pub utime: Duration,

	/// Time scheduled in user mode (ticks).
	pub utime_ticks: u64,

	/// Time scheduled in kernel mode (seconds).
	pub stime: Duration,

	/// Time scheduled in kernel mode (ticks).
	pub stime_ticks: u64,

	/// Time waited-for child processes were scheduled in user mode (seconds).
	pub cutime: Duration,

	/// Time waited-for child processes were scheduled in user mode (ticks).
	pub cutime_ticks: i64,

	/// Time waited-for child processes were scheduled in kernel mode (seconds).
	pub cstime: Duration,

	/// Time waited-for child processes were scheduled in kernel mode (ticks).
	pub cstime_ticks: i64,

	/// Priority value (-100..-2 | 0..39).
	pub priority: i64,

	/// Nice value (-20..19).
	pub nice: i64,

	/// Number of threads in the process.
	pub num_threads: i64,

	/// Unmaintained field since linux 2.6.17, always 0.
	pub itrealvalue: i64,

	/// Time the process was started after system boot (seconds).
	pub starttime: Duration,

	/// Time the process was started after system boot (ticks).
	pub starttime_ticks: u128,

	/// Virtual memory size in bytes.
	pub vsize: u64,

	/// Resident Set Size (bytes).
	pub rss: i64,

	/// Current soft limit on process RSS (bytes).
	pub rsslim: u64,

	// These values are memory addresses
	startcode: u64,
	endcode: u64,
	startstack: u64,
	kstkesp: u64,
	kstkeip: u64,

	// Signal bitmaps.
	// These are obsolete, use `/proc/[pid]/status` instead.
	signal: u64,
	blocked: u64,
	sigignore: u64,
	sigcatch: u64,

	/// Channel the process is waiting on (address of a system call).
	pub wchan: u64,

	// Number of pages swapped (not maintained).
	// pub nswap: u64,

	// Number of pages swapped for child processes (not maintained).
	// pub cnswap: u64,
	/// Signal sent to parent when process dies.
	pub exit_signal: i32,

	/// Number of the CPU the process was last executed on.
	pub processor: i32,

	/// Real-time scheduling priority (0 | 1..99).
	pub rt_priority: u32,

	/// Scheduling policy.
	pub policy: u64,

	/// Aggregated block I/O delays (seconds).
	pub delayacct_blkio: Option<Duration>,

	/// Aggregated block I/O delays (ticks).
	pub delayacct_blkio_ticks: Option<u128>,

	/// Guest time of the process (seconds).
	pub guest_time: Option<Duration>,

	/// Guest time of the process (ticks).
	pub guest_time_ticks: Option<u64>,

	/// Guest time of the process's children (seconds).
	pub cguest_time: Option<Duration>,

	/// Guest time of the process's children (ticks).
	pub cguest_time_ticks: Option<i64>,

	// More memory addresses.
	start_data: Option<u64>,
	end_data: Option<u64>,
	start_brk: Option<u64>,
	arg_start: Option<u64>,
	arg_end: Option<u64>,
	env_start: Option<u64>,
	env_end: Option<u64>,

	/// The thread's exit status.
	pub exit_code: Option<i32>,
}

impl FromStr for ProcfsStat {
	type Err = Error;

	fn from_str(contents: &str) -> Result<Self> {
		let missing_stat_data = |contents: &str| -> Error {
			Error::MissingData {
				path: STAT.into(),
				contents: contents.to_string(),
			}
		};
		// We parse the comm field and everything before it seperately since
		// the comm field is delimited by parens and can contain spaces
		let (pid_field, leftover) = contents
			.find('(')
			.map(|i| contents.split_at(i - 1))
			.ok_or_else(|| missing_stat_data(contents))?;
		let (comm_field, leftover) = leftover
			.rfind(')')
			.map(|i| leftover.split_at(i + 2))
			.ok_or_else(|| missing_stat_data(contents))?;

		let mut fields: Vec<&str> = vec![pid_field, &comm_field[2..comm_field.len() - 2]];
		fields.extend(leftover.trim_end().split_whitespace());

		if fields.len() < 41 {
			return Err(missing_stat_data(contents));
		}

		let parse_int = |err: std::num::ParseIntError| -> Error {
			Error::ParseInt {
				path: STAT.into(),
				contents: contents.to_string(),
				source: err,
			}
		};

		let parse_u32 = |s: &str| -> Result<u32> { s.parse().map_err(parse_int) };
		let parse_i32 = |s: &str| -> Result<i32> { s.parse().map_err(parse_int) };
		let parse_u64 = |s: &str| -> Result<u64> { s.parse().map_err(parse_int) };
		let parse_i64 = |s: &str| -> Result<i64> { s.parse().map_err(parse_int) };
		let parse_u128 = |s: &str| -> Result<u128> { s.parse().map_err(parse_int) };

		let pid = parse_u32(fields[0])?;
		let comm = fields[1].to_string();
		let state = Status::from_str(fields[2])?;

		let ppid = parse_u32(fields[3])?;
		let ppid = if ppid == 0 { None } else { Some(ppid) };

		let pgrp = parse_i32(fields[4])?;
		let session = parse_i32(fields[5])?;
		let tty_nr = parse_i32(fields[6])?;
		let tpgid = parse_i32(fields[7])?;
		let flags = parse_u32(fields[8])?;
		let minflt = parse_u64(fields[9])?;
		let cminflt = parse_u64(fields[10])?;
		let majflt = parse_u64(fields[11])?;
		let cmajflt = parse_u64(fields[12])?;

		let utime_ticks = parse_u64(fields[13])?;
		let utime = Duration::from_secs_f64(utime_ticks as f64 / *TICKS_PER_SECOND);

		let stime_ticks = parse_u64(fields[14])?;
		let stime = Duration::from_secs_f64(stime_ticks as f64 / *TICKS_PER_SECOND);

		let cutime_ticks = parse_i64(fields[15])?;
		let cutime = Duration::from_secs_f64(cutime_ticks as f64 / *TICKS_PER_SECOND);

		let cstime_ticks = parse_i64(fields[16])?;
		let cstime = Duration::from_secs_f64(cstime_ticks as f64 / *TICKS_PER_SECOND);

		let priority = parse_i64(fields[17])?;
		let nice = parse_i64(fields[18])?;
		let num_threads = parse_i64(fields[19])?;
		let itrealvalue = parse_i64(fields[20])?;

		let starttime_ticks = parse_u128(fields[21])?;
		let starttime = Duration::from_secs_f64(starttime_ticks as f64 / *TICKS_PER_SECOND);

		let vsize = parse_u64(fields[22])?;
		let rss = parse_i64(fields[23])? * *PAGE_SIZE as i64;
		let rsslim = parse_u64(fields[24])?;
		let startcode = parse_u64(fields[25])?;
		let endcode = parse_u64(fields[26])?;
		let startstack = parse_u64(fields[27])?;
		let kstkesp = parse_u64(fields[28])?;
		let kstkeip = parse_u64(fields[29])?;
		let signal = parse_u64(fields[30])?;
		let blocked = parse_u64(fields[31])?;
		let sigignore = parse_u64(fields[32])?;
		let sigcatch = parse_u64(fields[33])?;
		let wchan = parse_u64(fields[34])?;
		// let nswap = parse_u64(fields[35])?;
		// let cnswap = parse_u64(fields[36])?;
		let exit_signal = parse_i32(fields[37])?;
		let processor = parse_i32(fields[38])?;
		let rt_priority = parse_u32(fields[39])?;
		let policy = parse_u64(fields[40])?;

		// since kernel 2.6.18
		let delayacct_blkio_ticks = if fields.len() >= 42 {
			Some(parse_u128(fields[41])?)
		} else {
			None
		};
		let delayacct_blkio = delayacct_blkio_ticks
			.map(|val| Duration::from_secs_f64(val as f64 / *TICKS_PER_SECOND));

		// since kernel 2.6.24
		let (guest_time_ticks, cguest_time_ticks) = if fields.len() >= 44 {
			(Some(parse_u64(fields[42])?), Some(parse_i64(fields[43])?))
		} else {
			(None, None)
		};
		let guest_time =
			guest_time_ticks.map(|val| Duration::from_secs_f64(val as f64 / *TICKS_PER_SECOND));
		let cguest_time =
			cguest_time_ticks.map(|val| Duration::from_secs_f64(val as f64 / *TICKS_PER_SECOND));

		// since kernel 3.3
		let (start_data, end_data, start_brk) = if fields.len() >= 47 {
			(
				Some(parse_u64(fields[44])?),
				Some(parse_u64(fields[45])?),
				Some(parse_u64(fields[46])?),
			)
		} else {
			(None, None, None)
		};

		// since kernel 3.5
		let (arg_start, arg_end, env_start, env_end, exit_code) = if fields.len() >= 52 {
			(
				Some(parse_u64(fields[47])?),
				Some(parse_u64(fields[48])?),
				Some(parse_u64(fields[49])?),
				Some(parse_u64(fields[50])?),
				Some(parse_i32(fields[51])?),
			)
		} else {
			(None, None, None, None, None)
		};

		Ok(ProcfsStat {
			pid,
			comm,
			state,
			ppid,
			pgrp,
			session,
			tty_nr,
			tpgid,
			flags,
			minflt,
			cminflt,
			majflt,
			cmajflt,
			utime,
			utime_ticks,
			stime,
			stime_ticks,
			cutime,
			cutime_ticks,
			cstime,
			cstime_ticks,
			priority,
			nice,
			num_threads,
			itrealvalue,
			starttime,
			starttime_ticks,
			vsize,
			rss,
			rsslim,
			startcode,
			endcode,
			startstack,
			kstkesp,
			kstkeip,
			signal,
			blocked,
			sigignore,
			sigcatch,
			wchan,
			// nswap,
			// cnswap,
			exit_signal,
			processor,
			rt_priority,
			policy,
			delayacct_blkio,
			delayacct_blkio_ticks,
			guest_time,
			guest_time_ticks,
			cguest_time,
			cguest_time_ticks,
			start_data,
			end_data,
			start_brk,
			arg_start,
			arg_end,
			env_start,
			env_end,
			exit_code,
		})
	}
}

/// New function, not in Python psutil.
pub fn procfs_stat(pid: Pid) -> ProcessResult<ProcfsStat> {
	let contents =
		read_file(procfs_path(pid, STAT)).map_err(|e| psutil_error_to_process_error(e, pid))?;

	ProcfsStat::from_str(&contents).map_err(|e| psutil_error_to_process_error(e, pid))
}
