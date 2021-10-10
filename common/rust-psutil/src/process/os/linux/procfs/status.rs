use std::collections::HashMap;
use std::str::FromStr;

use crate::process::os::unix::{Gid, Uid};
use crate::process::{procfs_path, psutil_error_to_process_error, ProcessResult};
use crate::{read_file, Error, Pid, Result};

const STATUS: &str = "status";

// TODO: rest of the fields
/// New struct, not in Python psutil.
#[derive(Clone, Debug)]
pub struct ProcfsStatus {
	pub uid: [Uid; 4],

	pub gid: [Gid; 4],

	/// Voluntary context switches.
	pub voluntary_ctxt_switches: Option<u64>,

	/// Non-voluntary context switches.
	pub nonvoluntary_ctxt_switches: Option<u64>,
}

impl FromStr for ProcfsStatus {
	type Err = Error;

	fn from_str(contents: &str) -> Result<Self> {
		let missing_status_data = |contents: &str| -> Error {
			Error::MissingData {
				path: STATUS.into(),
				contents: contents.to_string(),
			}
		};

		let map = contents
			.lines()
			.map(|line| {
				let fields = match line.splitn(2, ':').collect::<Vec<_>>() {
					fields if fields.len() == 2 => Ok(fields),
					_ => Err(missing_status_data(line)),
				}?;

				Ok((fields[0], fields[1].trim()))
			})
			.collect::<Result<HashMap<&str, &str>>>()?;

		let parse_u32 = |s: &str| -> Result<u32> {
			s.parse().map_err(|err| Error::ParseInt {
				path: STATUS.into(),
				contents: contents.to_string(),
				source: err,
			})
		};
		let parse_u64 = |s: &str| -> Result<u64> {
			s.parse().map_err(|err| Error::ParseInt {
				path: STATUS.into(),
				contents: contents.to_string(),
				source: err,
			})
		};

		let get = |key: &str| -> Result<&str> {
			map.get(key)
				.copied()
				.ok_or_else(|| missing_status_data(contents))
		};

		let uid_fields = match get("Uid")?.split_whitespace().collect::<Vec<_>>() {
			fields if fields.len() >= 4 => Ok(fields),
			_ => Err(missing_status_data(contents)),
		}?;

		let uid = [
			parse_u32(uid_fields[0])?,
			parse_u32(uid_fields[1])?,
			parse_u32(uid_fields[2])?,
			parse_u32(uid_fields[3])?,
		];

		let gid_fields = match get("Gid")?.split_whitespace().collect::<Vec<_>>() {
			fields if fields.len() >= 4 => Ok(fields),
			_ => Err(missing_status_data(contents)),
		}?;

		let gid = [
			parse_u32(gid_fields[0])?,
			parse_u32(gid_fields[1])?,
			parse_u32(gid_fields[2])?,
			parse_u32(gid_fields[3])?,
		];

		let voluntary_ctxt_switches = map
			.get("voluntary_ctxt_switches")
			.map(|entry| -> Result<u64> { parse_u64(entry) })
			.transpose()?;
		let nonvoluntary_ctxt_switches = map
			.get("nonvoluntary_ctxt_switches")
			.map(|entry| -> Result<u64> { parse_u64(entry) })
			.transpose()?;

		Ok(ProcfsStatus {
			uid,
			gid,
			voluntary_ctxt_switches,
			nonvoluntary_ctxt_switches,
		})
	}
}

/// New function, not in Python psutil.
pub fn procfs_status(pid: Pid) -> ProcessResult<ProcfsStatus> {
	let contents =
		read_file(procfs_path(pid, STATUS)).map_err(|e| psutil_error_to_process_error(e, pid))?;

	ProcfsStatus::from_str(&contents).map_err(|e| psutil_error_to_process_error(e, pid))
}
