use std::str::FromStr;
use std::time::Duration;

use crate::cpu::CpuTimes;
use crate::{read_file, Count, Error, Result, TICKS_PER_SECOND};

const PROC_STAT: &str = "/proc/stat";

impl FromStr for CpuTimes {
	type Err = Error;

	fn from_str(line: &str) -> Result<Self> {
		let fields = line
			.split_whitespace()
			.skip(1)
			.map(|entry| {
				entry.parse().map_err(|err| Error::ParseInt {
					path: PROC_STAT.into(),
					contents: line.to_string(),
					source: err,
				})
			})
			.collect::<Result<Vec<Count>>>()?
			.into_iter()
			.map(|entry| Duration::from_secs_f64(entry as f64 / *TICKS_PER_SECOND))
			.collect::<Vec<Duration>>();

		if fields.len() < 7 {
			return Err(Error::MissingData {
				path: PROC_STAT.into(),
				contents: line.to_string(),
			});
		}

		let user = fields[0];
		let nice = fields[1];
		let system = fields[2];
		let idle = fields[3];
		let iowait = fields[4];
		let irq = fields[5];
		let softirq = fields[6];

		// since kernel 2.6.11
		let steal = if fields.len() >= 8 {
			Some(fields[7])
		} else {
			None
		};
		// since kernel 2.6.24
		let guest = if fields.len() >= 9 {
			Some(fields[8])
		} else {
			None
		};
		// since kernel 2.6.33
		let guest_nice = if fields.len() >= 10 {
			Some(fields[9])
		} else {
			None
		};

		Ok(CpuTimes {
			user,
			system,
			idle,
			nice,
			iowait,
			irq,
			softirq,
			steal,
			guest,
			guest_nice,
		})
	}
}

pub fn cpu_times() -> Result<CpuTimes> {
	let contents = read_file(PROC_STAT)?;
	let lines: Vec<_> = contents.lines().collect();

	if lines.is_empty() {
		return Err(Error::MissingData {
			path: PROC_STAT.into(),
			contents,
		});
	}

	CpuTimes::from_str(lines[0])
}

pub fn cpu_times_percpu() -> Result<Vec<CpuTimes>> {
	let contents = read_file(PROC_STAT)?;
	let lines: Vec<_> = contents
		.lines()
		.skip(1)
		.take_while(|line| line.starts_with("cpu"))
		.collect();

	if lines.is_empty() {
		return Err(Error::MissingData {
			path: PROC_STAT.into(),
			contents,
		});
	}

	lines.into_iter().map(CpuTimes::from_str).collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_parse_cpu_times() {
		let line = "cpu  11867200 6935 2978038 19104017 85955 502109 144021 0 0 0";
		let result = CpuTimes::from_str(line).unwrap();
		let expected = CpuTimes {
			user: Duration::from_secs_f64(11_867_200_f64 / *TICKS_PER_SECOND),
			nice: Duration::from_secs_f64(6935_f64 / *TICKS_PER_SECOND),
			system: Duration::from_secs_f64(2_978_038_f64 / *TICKS_PER_SECOND),
			idle: Duration::from_secs_f64(19_104_017_f64 / *TICKS_PER_SECOND),
			iowait: Duration::from_secs_f64(85955_f64 / *TICKS_PER_SECOND),
			irq: Duration::from_secs_f64(502_109_f64 / *TICKS_PER_SECOND),
			softirq: Duration::from_secs_f64(144_021_f64 / *TICKS_PER_SECOND),
			steal: Some(Duration::default()),
			guest: Some(Duration::default()),
			guest_nice: Some(Duration::default()),
		};
		assert_eq!(result, expected);
	}
}
