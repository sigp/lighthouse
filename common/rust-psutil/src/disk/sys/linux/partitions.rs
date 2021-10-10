use std::path::PathBuf;
use std::str::FromStr;

use unescape::unescape;

use crate::{read_file, Error, Result};

use crate::disk::{FileSystem, Partition};

const PROC_MOUNTS: &str = "/proc/mounts";

impl FromStr for Partition {
	type Err = Error;

	fn from_str(line: &str) -> Result<Partition> {
		// Example: `/dev/sda3 /home ext4 rw,relatime,data=ordered 0 0`
		match line.split_whitespace().collect::<Vec<_>>() {
			fields if fields.len() >= 4 => {
				Ok(Partition {
					device: String::from(fields[0]),
					// need to unescape since some characters are escaped by default like the space character
					// https://github.com/cjbassi/ytop/issues/29
					mountpoint: PathBuf::from(unescape(fields[1]).unwrap()), // TODO: can this unwrap fail?
					filesystem: FileSystem::from_str(fields[2]).unwrap(),    // infallible unwrap
					mount_options: String::from(fields[3]),
				})
			}
			_ => Err(Error::MissingData {
				path: PROC_MOUNTS.into(),
				contents: line.to_string(),
			}),
		}
	}
}

pub fn partitions() -> Result<Vec<Partition>> {
	read_file(PROC_MOUNTS)?
		.lines()
		.map(|line| Partition::from_str(line))
		.collect()
}
