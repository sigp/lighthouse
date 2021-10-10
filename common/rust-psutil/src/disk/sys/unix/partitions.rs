// https://github.com/heim-rs/heim/blob/master/heim-disk/src/sys/unix/bindings/mod.rs
// https://github.com/heim-rs/heim/blob/master/heim-disk/src/sys/unix/partitions.rs

use std::ffi::CStr;
use std::io;
use std::mem;
use std::path::PathBuf;
use std::ptr;
use std::str::FromStr;

use nix::libc;

use crate::disk::{FileSystem, Partition};

#[allow(unused)]
pub const MNT_WAIT: libc::c_int = 1;
pub const MNT_NOWAIT: libc::c_int = 2;

extern "C" {
	fn getfsstat64(buf: *mut libc::statfs, bufsize: libc::c_int, flags: libc::c_int)
		-> libc::c_int;
}

// TODO: Since `MNT_NOWAIT` might return inconsistent data (see `getfsstat(2)`)
// it might be a good idea (maybe?) to wrap it into a `blocking` call
// and switch to the `MNT_WAIT` mode?
// Should be considered later.
fn mounts() -> io::Result<Vec<libc::statfs>> {
	let expected_len = unsafe { getfsstat64(ptr::null_mut(), 0, MNT_NOWAIT) };
	let mut mounts: Vec<libc::statfs> = Vec::with_capacity(expected_len as usize);
	let result = unsafe {
		getfsstat64(
			mounts.as_mut_ptr(),
			mem::size_of::<libc::statfs>() as libc::c_int * expected_len,
			MNT_NOWAIT,
		)
	};
	if result == -1 {
		return Err(io::Error::last_os_error());
	} else {
		debug_assert!(
			expected_len == result,
			"Expected {} statfs entries, but got {}",
			expected_len,
			result
		);
		unsafe {
			mounts.set_len(result as usize);
		}
	}

	Ok(mounts)
}

impl From<libc::statfs> for Partition {
	fn from(stat: libc::statfs) -> Partition {
		let device = unsafe {
			CStr::from_ptr(stat.f_mntfromname.as_ptr())
				.to_string_lossy()
				.to_string()
		};
		let filesystem = FileSystem::from_str(unsafe {
			&CStr::from_ptr(stat.f_fstypename.as_ptr()).to_string_lossy()
		})
		.unwrap();
		let mountpoint = PathBuf::from(unsafe {
			CStr::from_ptr(stat.f_mntonname.as_ptr())
				.to_string_lossy()
				.to_string()
		});
		let flags = stat.f_flags;

		Partition {
			device,
			mountpoint,
			filesystem,
			mount_options: "".to_owned(), // TODO
		}
	}
}

pub fn partitions() -> io::Result<Vec<Partition>> {
	Ok(mounts()?.into_iter().map(Partition::from).collect())
}
