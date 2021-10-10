// https://github.com/heim-rs/heim/blob/master/heim-process/src/sys/macos/bindings/process.rs

use std::convert::TryFrom;

use nix::libc;

use crate::process::Status;
use crate::ParseStatusError;

// Process status values, declared at `bsd/sys/proc.h`
// ex. http://fxr.watson.org/fxr/source/bsd/sys/proc.h?v=xnu-792.6.70#L149
// Used in `extern_proc.p_stat` field

/// Process being created by fork.
const SIDL: libc::c_char = 1;
/// Currently runnable.
const SRUN: libc::c_char = 2;
/// Sleeping on an address.
const SSLEEP: libc::c_char = 3;
/// Process debugging or suspension.
const SSTOP: libc::c_char = 4;
/// Awaiting collection by parent.
const SZOMB: libc::c_char = 5;

impl TryFrom<libc::c_char> for Status {
	type Error = ParseStatusError;

	fn try_from(value: libc::c_char) -> Result<Status, Self::Error> {
		match value {
			SIDL => Ok(Status::Idle),
			SRUN => Ok(Status::Running),
			SSLEEP => Ok(Status::Sleeping),
			SSTOP => Ok(Status::Stopped),
			SZOMB => Ok(Status::Zombie),
			other => Err(ParseStatusError::IncorrectChar {
				contents: other.to_string(),
			}),
		}
	}
}
