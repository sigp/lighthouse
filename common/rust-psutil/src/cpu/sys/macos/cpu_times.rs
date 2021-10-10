// https://github.com/heim-rs/heim/blob/master/heim-cpu/src/sys/macos/times.rs
// https://github.com/heim-rs/heim/blob/master/heim-cpu/src/sys/macos/bindings.rs
// https://github.com/heim-rs/heim/blob/master/heim-common/src/sys/macos/mod.rs

use std::io;
use std::mem;
use std::ptr;
use std::slice;
use std::time::Duration;

use mach::kern_return::{self, kern_return_t};
use mach::mach_port;
use mach::mach_types::{host_name_port_t, host_t};
use mach::message::mach_msg_type_number_t;
use mach::traps::mach_task_self;
use mach::vm_types::{integer_t, natural_t, vm_address_t, vm_map_t, vm_size_t};
use nix::libc;

use crate::cpu::CpuTimes;
use crate::{Result, TICKS_PER_SECOND};

const PROCESSOR_CPU_LOAD_INFO: libc::c_int = 2;
const HOST_CPU_LOAD_INFO: libc::c_int = 3;
const CPU_STATE_USER: usize = 0;
const CPU_STATE_SYSTEM: usize = 1;
const CPU_STATE_IDLE: usize = 2;
const CPU_STATE_NICE: usize = 3;

#[allow(non_camel_case_types)]
type processor_flavor_t = libc::c_int;
#[allow(non_camel_case_types)]
type processor_info_array_t = *mut integer_t;
/// https://developer.apple.com/documentation/kernel/host_flavor_t?language=objc
#[allow(non_camel_case_types)]
type host_flavor_t = integer_t;
/// https://developer.apple.com/documentation/kernel/host_info64_t?language=objc
#[allow(non_camel_case_types)]
type host_info64_t = *mut integer_t;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Hash, PartialOrd, PartialEq, Eq, Ord)]
struct host_cpu_load_info {
	user: natural_t,
	system: natural_t,
	idle: natural_t,
	nice: natural_t,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Hash, PartialOrd, PartialEq, Eq, Ord)]
struct processor_cpu_load_info {
	user: natural_t,
	system: natural_t,
	idle: natural_t,
	nice: natural_t,
}

extern "C" {
	fn host_processor_info(
		host: host_t,
		flavor: processor_flavor_t,
		out_processor_count: *mut natural_t,
		out_processor_info: *mut processor_info_array_t,
		out_processor_infoCnt: *mut mach_msg_type_number_t,
	) -> kern_return_t;

	fn vm_deallocate(
		target_task: vm_map_t,
		address: vm_address_t,
		size: vm_size_t,
	) -> kern_return_t;

	fn mach_host_self() -> host_name_port_t;

	/// https://developer.apple.com/documentation/kernel/1502863-host_statistics64?language=objc
	fn host_statistics64(
		host_priv: host_t,
		flavor: host_flavor_t,
		host_info_out: host_info64_t,
		host_info_outCnt: *const mach_msg_type_number_t,
	) -> kern_return_t;
}

#[allow(trivial_casts)]
unsafe fn processor_load_info() -> io::Result<Vec<processor_cpu_load_info>> {
	let port = mach_host_self();
	let mut cpu_count = 0;
	let mut processor_info: processor_info_array_t = ptr::null_mut();
	let mut cpu_info_count = 0;

	let result = host_processor_info(
		port,
		PROCESSOR_CPU_LOAD_INFO,
		&mut cpu_count,
		&mut processor_info,
		&mut cpu_info_count,
	);

	let port_result = mach_port::mach_port_deallocate(mach_task_self(), port);
	if port_result != kern_return::KERN_SUCCESS {
		return Err(io::Error::last_os_error());
	}

	if result != kern_return::KERN_SUCCESS {
		Err(io::Error::last_os_error())
	} else {
		let cpu_info = slice::from_raw_parts(processor_info, cpu_info_count as usize);
		// Could use a `::std::mem::transmute` probably, but this is okay too
		let mut stats = Vec::with_capacity(cpu_count as usize);
		for chunk in cpu_info.chunks(4) {
			stats.push(processor_cpu_load_info {
				user: chunk[CPU_STATE_USER] as natural_t,
				system: chunk[CPU_STATE_SYSTEM] as natural_t,
				idle: chunk[CPU_STATE_IDLE] as natural_t,
				nice: chunk[CPU_STATE_NICE] as natural_t,
			})
		}

		let result = vm_deallocate(
			mach_task_self(),
			processor_info as vm_address_t,
			cpu_info_count as vm_size_t * std::mem::size_of::<natural_t>(),
		);
		if result != kern_return::KERN_SUCCESS {
			return Err(io::Error::last_os_error());
		}

		Ok(stats)
	}
}

#[allow(trivial_casts)]
unsafe fn cpu_load_info() -> io::Result<host_cpu_load_info> {
	let port = mach_host_self();
	let mut stats = host_cpu_load_info::default();
	// TODO: Move to const
	let count = mem::size_of::<host_cpu_load_info>() / mem::size_of::<integer_t>();

	let result = host_statistics64(
		port,
		HOST_CPU_LOAD_INFO,
		&mut stats as *mut _ as host_info64_t,
		&count as *const _ as *const mach_msg_type_number_t,
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

impl From<host_cpu_load_info> for CpuTimes {
	fn from(info: host_cpu_load_info) -> CpuTimes {
		let ticks = *TICKS_PER_SECOND;

		CpuTimes {
			user: Duration::from_secs_f64(f64::from(info.user) / ticks),
			system: Duration::from_secs_f64(f64::from(info.system) / ticks),
			idle: Duration::from_secs_f64(f64::from(info.idle) / ticks),
			nice: Duration::from_secs_f64(f64::from(info.nice) / ticks),
		}
	}
}

impl From<processor_cpu_load_info> for CpuTimes {
	fn from(info: processor_cpu_load_info) -> CpuTimes {
		let ticks = *TICKS_PER_SECOND;

		CpuTimes {
			user: Duration::from_secs_f64(f64::from(info.user) / ticks),
			system: Duration::from_secs_f64(f64::from(info.system) / ticks),
			idle: Duration::from_secs_f64(f64::from(info.idle) / ticks),
			nice: Duration::from_secs_f64(f64::from(info.nice) / ticks),
		}
	}
}

pub fn cpu_times() -> Result<CpuTimes> {
	let info = unsafe { cpu_load_info()? };

	Ok(info.into())
}

pub fn cpu_times_percpu() -> Result<Vec<CpuTimes>> {
	let processors = unsafe { processor_load_info()? };

	Ok(processors
		.into_iter()
		.map(|processor| processor.into())
		.collect())
}
