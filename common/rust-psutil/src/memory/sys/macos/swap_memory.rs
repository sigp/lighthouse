// https://github.com/heim-rs/heim/blob/master/heim-memory/src/sys/macos/swap.rs
// https://github.com/heim-rs/heim/blob/master/heim-memory/src/sys/macos/bindings.rs
// https://github.com/heim-rs/heim/blob/master/heim-common/src/sys/macos/mod.rs

use std::io;
use std::mem;
use std::ptr;

use nix::libc;

use crate::memory::{host_vm_info, SwapMemory};
use crate::{Result, PAGE_SIZE};

const CTL_VM: libc::c_int = 2;
const VM_SWAPUSAGE: libc::c_int = 5;

unsafe fn vm_swapusage() -> io::Result<libc::xsw_usage> {
	let mut name: [i32; 2] = [CTL_VM, VM_SWAPUSAGE];
	let mut value = mem::MaybeUninit::<libc::xsw_usage>::uninit();
	let mut length = mem::size_of::<libc::xsw_usage>();

	let result = libc::sysctl(
		name.as_mut_ptr(),
		2,
		value.as_mut_ptr() as *mut libc::c_void,
		&mut length,
		ptr::null_mut(),
		0,
	);

	if result == 0 {
		let value = value.assume_init();
		Ok(value)
	} else {
		Err(io::Error::last_os_error())
	}
}

pub fn swap_memory() -> Result<SwapMemory> {
	let xsw_usage = unsafe { vm_swapusage()? };
	let vm_stats = unsafe { host_vm_info()? };
	let page_size = *PAGE_SIZE;

	let total = u64::from(xsw_usage.xsu_total);
	let used = u64::from(xsw_usage.xsu_used);
	let free = u64::from(xsw_usage.xsu_avail);
	let swapped_in = u64::from(vm_stats.pageins) * page_size;
	let swapped_out = u64::from(vm_stats.pageouts) * page_size;

	let percent = ((used as f64 / total as f64) * 100.0) as f32;

	Ok(SwapMemory {
		total,
		used,
		free,
		percent,
		swapped_in,
		swapped_out,
	})
}
