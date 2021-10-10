use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{read_file, Error, Result};

const PROC_STAT: &str = "/proc/stat";

fn parse_boot_time(line: &str) -> Result<SystemTime> {
	let fields = match line.split_whitespace().collect::<Vec<_>>() {
		fields if fields.len() >= 2 => Ok(fields),
		_ => Err(Error::MissingData {
			path: PROC_STAT.into(),
			contents: line.to_string(),
		}),
	}?;

	let parsed = fields[1].parse().map_err(|err| Error::ParseInt {
		path: PROC_STAT.into(),
		contents: line.to_string(),
		source: err,
	})?;
	let boot_time = UNIX_EPOCH + Duration::from_secs(parsed);

	Ok(boot_time)
}

// TODO: cache with https://github.com/jaemk/cached once `pub fn` is supported
pub fn boot_time() -> Result<SystemTime> {
	let contents = read_file(PROC_STAT)?;
	let line = contents
		.lines()
		.find(|line| line.starts_with("btime "))
		.ok_or(Error::MissingData {
			path: PROC_STAT.into(),
			contents: contents.clone(),
		})?;

	parse_boot_time(line)
}
