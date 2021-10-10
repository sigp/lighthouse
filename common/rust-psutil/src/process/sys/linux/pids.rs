use std::path::Path;

use crate::{read_dir, Pid, Result};

// TODO: should we return an `io::Result<Vec<io::Result<<Pid>>>` instead?
pub fn pids() -> Result<Vec<Pid>> {
	let mut pids = Vec::new();

	for entry in read_dir("/proc")? {
		let filename = entry.file_name();
		if let Ok(pid) = filename.to_string_lossy().parse::<Pid>() {
			pids.push(pid);
		}
	}

	Ok(pids)
}

pub fn pid_exists(pid: Pid) -> bool {
	Path::new(&format!("/proc/{}", pid)).exists()
}
