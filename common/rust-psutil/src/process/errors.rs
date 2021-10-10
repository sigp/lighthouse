use std::io;

use crate::{Error, Pid};

pub type ProcessResult<T> = std::result::Result<T, ProcessError>;

#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
	#[error("Process {} does not exist", pid)]
	NoSuchProcess { pid: Pid },

	#[error("Process {} is a zombie", pid)]
	ZombieProcess { pid: Pid },

	#[error("Access denied for process {}", pid)]
	AccessDenied { pid: Pid },

	#[error("psutil error for process {}: {}", pid, source)]
	PsutilError { pid: Pid, source: Error },
}

pub(crate) fn psutil_error_to_process_error(e: Error, pid: Pid) -> ProcessError {
	match e {
		Error::ReadFile { source, .. } | Error::OsError { source, .. } => {
			io_error_to_process_error(source, pid)
		}
		_ => ProcessError::PsutilError { pid, source: e },
	}
}

pub(crate) fn io_error_to_process_error(e: io::Error, pid: Pid) -> ProcessError {
	match e.kind() {
		io::ErrorKind::NotFound => ProcessError::NoSuchProcess { pid },
		io::ErrorKind::PermissionDenied => ProcessError::AccessDenied { pid },
		_ => ProcessError::PsutilError {
			pid,
			source: Error::OsError { source: e },
		},
	}
}
