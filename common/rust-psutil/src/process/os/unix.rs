use crate::process::{Process, ProcessResult};
use crate::Count;

#[cfg(target_os = "linux")]
use crate::process::os::linux::{ProcessExt as _, ProcfsStatus};

pub type Uid = u32;
pub type Gid = u32;

pub struct Uids {
	pub real: Uid,
	pub effective: Uid,
	pub saved: Uid,
}

pub struct Gids {
	pub real: Gid,
	pub effective: Gid,
	pub saved: Gid,
}

#[cfg(target_os = "linux")]
impl From<ProcfsStatus> for Uids {
	fn from(procfs_status: ProcfsStatus) -> Self {
		Uids {
			real: procfs_status.uid[0],
			effective: procfs_status.uid[1],
			saved: procfs_status.uid[2],
		}
	}
}

#[cfg(target_os = "linux")]
impl From<ProcfsStatus> for Gids {
	fn from(procfs_status: ProcfsStatus) -> Self {
		Gids {
			real: procfs_status.gid[0],
			effective: procfs_status.gid[1],
			saved: procfs_status.gid[2],
		}
	}
}

pub trait ProcessExt {
	fn uids(&self) -> ProcessResult<Uids>;

	fn gids(&self) -> ProcessResult<Gids>;

	fn terminal(&self) -> Option<String>;

	fn num_fds(&self) -> Count;
}

impl ProcessExt for Process {
	fn uids(&self) -> ProcessResult<Uids> {
		#[cfg(target_os = "linux")]
		{
			let procfs_status = self.procfs_status()?;

			Ok(Uids::from(procfs_status))
		}
		#[cfg(not(any(target_os = "linux")))]
		{
			todo!()
		}
	}

	fn gids(&self) -> ProcessResult<Gids> {
		#[cfg(target_os = "linux")]
		{
			let procfs_status = self.procfs_status()?;

			Ok(Gids::from(procfs_status))
		}
		#[cfg(not(any(target_os = "linux")))]
		{
			todo!()
		}
	}

	fn terminal(&self) -> Option<String> {
		todo!()
	}

	fn num_fds(&self) -> Count {
		todo!()
	}
}
