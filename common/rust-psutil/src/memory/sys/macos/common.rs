// https://github.com/heim-rs/heim/blob/master/heim-memory/src/sys/macos/memory.rs
// https://github.com/heim-rs/heim/blob/master/heim-memory/src/sys/macos/swap.rs
// https://github.com/heim-rs/heim/blob/master/heim-memory/src/sys/macos/bindings.rs
// https://github.com/heim-rs/heim/blob/master/heim-common/src/sys/macos/mod.rs

use std::io;

use mach::kern_return::{self, kern_return_t};
use mach::mach_port;
use mach::mach_types::{host_name_port_t, host_t};
use mach::message::mach_msg_type_number_t;
use mach::traps::mach_task_self;
use mach::vm_types::{integer_t, natural_t};
use nix::libc;

const HOST_VM_INFO64: libc::c_int = 4;
const HOST_VM_INFO64_COUNT: libc::c_uint = 38;

/// https://developer.apple.com/documentation/kernel/host_flavor_t?language=objc
#[allow(non_camel_case_types)]
type host_flavor_t = integer_t;
/// https://developer.apple.com/documentation/kernel/host_info64_t?language=objc
#[allow(non_camel_case_types)]
type host_info64_t = *mut integer_t;

extern "C" {
	fn mach_host_self() -> host_name_port_t;

	/// https://developer.apple.com/documentation/kernel/1502863-host_statistics64?language=objc
	fn host_statistics64(
		host_priv: host_t,
		flavor: host_flavor_t,
		host_info_out: host_info64_t,
		host_info_outCnt: *const mach_msg_type_number_t,
	) -> kern_return_t;
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Hash, PartialOrd, PartialEq, Eq, Ord)]
pub struct vm_statistics64 {
	pub free_count: natural_t,
	pub active_count: natural_t,
	pub inactive_count: natural_t,
	pub wire_count: natural_t,
	pub zero_fill_count: u64,
	pub reactivations: u64,
	pub pageins: u64,
	pub pageouts: u64,
	pub faults: u64,
	pub cow_faults: u64,
	pub lookups: u64,
	pub hits: u64,
	pub purges: u64,
	pub purgeable_count: natural_t,
	pub speculative_count: natural_t,
	pub decompressions: u64,
	pub compressions: u64,
	pub swapins: u64,
	pub swapouts: u64,
	pub compressor_page_count: natural_t,
	pub throttled_count: natural_t,
	pub external_page_count: natural_t,
	pub internal_page_count: natural_t,
	pub total_uncompressed_pages_in_compressor: u64,
}

#[allow(trivial_casts)]
pub unsafe fn host_vm_info() -> io::Result<vm_statistics64> {
	let port = mach_host_self();
	let mut stats = vm_statistics64::default();
	let count = HOST_VM_INFO64_COUNT;

	let result = host_statistics64(
		port,
		HOST_VM_INFO64,
		&mut stats as *mut _ as host_info64_t,
		// We can't pass the reference to const here,
		// it leads to `EXC_BAD_ACCESS` for some reasons,
		// so we are copying it to a stack and passing a reference to a local copy
		&count,
	);

	let port_result = mach_port::mach_port_deallocate(mach_task_self(), port);
	// Technically it is a programming bug and we are should panic probably,
	// but it is okay as is
	if port_result != kern_return::KERN_SUCCESS {
		return Err(io::Error::last_os_error());
	}

	if result != kern_return::KERN_SUCCESS {
		Err(io::Error::last_os_error())
	} else {
		Ok(stats)
	}
}
