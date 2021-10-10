use std::time::Duration;

use crate::{read_file, Error, Result};

const PROC_UPTIME: &str = "/proc/uptime";

fn parse_uptime(contents: &str) -> Result<Duration> {
	let fields = match contents.split_whitespace().collect::<Vec<_>>() {
		fields if fields.len() >= 2 => Ok(fields),
		_ => Err(Error::MissingData {
			path: PROC_UPTIME.into(),
			contents: contents.to_string(),
		}),
	}?;

	let parsed = fields[0].parse().map_err(|err| Error::ParseFloat {
		path: PROC_UPTIME.into(),
		contents: contents.to_string(),
		source: err,
	})?;
	let uptime = Duration::from_secs_f64(parsed);

	Ok(uptime)
}

/// New function, not in Python psutil.
pub fn uptime() -> Result<Duration> {
	parse_uptime(&read_file(PROC_UPTIME)?)
}

#[cfg(test)]
mod unit_tests {
	use super::*;

	#[test]
	fn test_uptime() {
		assert!(uptime().unwrap().as_secs() > 0);
	}

	#[test]
	fn test_parse_uptime() {
		assert_eq!(
			parse_uptime("12489513.08 22906637.29\n").unwrap(),
			Duration::from_secs_f64(12_489_513.08)
		);
	}
}
