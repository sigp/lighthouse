// https://github.com/heim-rs/heim/blob/master/heim-memory/src/sys/macos/memory.rs
// https://github.com/heim-rs/heim/blob/master/heim-memory/src/sys/macos/bindings.rs
// https://github.com/heim-rs/heim/blob/master/heim-common/src/sys/macos/mod.rs

use std::io;
use std::mem;
use std::ptr;

use nix::libc;

use crate::memory::{host_vm_info, VirtualMemory};
use crate::{Result, PAGE_SIZE};

const CTL_HW: libc::c_int = 6;
const HW_MEMSIZE: libc::c_int = 24;

#[allow(trivial_casts)]
unsafe fn hw_memsize() -> io::Result<u64> {
	let mut name: [i32; 2] = [CTL_HW, HW_MEMSIZE];
	let mut value = 0u64;
	let mut length = mem::size_of::<u64>();

	let result = libc::sysctl(
		name.as_mut_ptr(),
		2,
		&mut value as *mut u64 as *mut libc::c_void,
		&mut length,
		ptr::null_mut(),
		0,
	);

	if result == 0 {
		Ok(value)
	} else {
		Err(io::Error::last_os_error())
	}
}

pub fn virtual_memory() -> Result<VirtualMemory> {
	let total = unsafe { hw_memsize()? };
	let vm_stats = unsafe { host_vm_info()? };
	let page_size = *PAGE_SIZE;

	let available = u64::from(vm_stats.active_count + vm_stats.free_count) * page_size;
	let used = u64::from(vm_stats.active_count + vm_stats.wire_count) * page_size;
	let free = u64::from(vm_stats.free_count - vm_stats.speculative_count) * page_size;
	let active = u64::from(vm_stats.active_count) * page_size;
	let inactive = u64::from(vm_stats.inactive_count) * page_size;

	let wired = u64::from(vm_stats.wire_count) * page_size;

	let percent = (((total as f64 - available as f64) / total as f64) * 100.0) as f32;

	Ok(VirtualMemory {
		total,
		available,
		used,
		free,
		percent,
		active,
		inactive,
		wired,
	})
}
