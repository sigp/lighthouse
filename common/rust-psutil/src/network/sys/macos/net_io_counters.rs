// https://github.com/heim-rs/heim/blob/master/heim-net/src/sys/macos/bindings.rs
// https://github.com/heim-rs/heim/blob/master/heim-net/src/sys/macos/counters.rs

use std::collections::HashMap;
use std::io;
use std::mem;
use std::ptr;

use nix::libc;

use crate::network::NetIoCounters;
use crate::{Error, Result};

#[derive(Debug)]
struct Routes {
	position: usize,
	data: Vec<u8>,
}

impl Iterator for Routes {
	type Item = if_msghdr2;

	fn next(&mut self) -> Option<Self::Item> {
		loop {
			if self.position == self.data.len() {
				return None;
			}

			let data_ptr = unsafe { self.data.as_ptr().add(self.position) };

			// In order not to read uninitialized memory (leading to heap-buffer-overflow),
			// which might happen if the whole `libc::if_msghdr` struct would be used here,
			// we are going to read as small as possible bytes amount
			// and see if that would be enough to determine the `ifm_type`
			assert!(
				self.position + mem::size_of::<if_msghdr_partial>() < self.data.len(),
				"Not enough data to read the `if_msghdr` header, need at least {} bytes, got {}",
				mem::size_of::<if_msghdr_partial>(),
				self.data.len() - self.position,
			);

			let hdr = unsafe {
				let mut maybe_hdr = mem::MaybeUninit::<if_msghdr_partial>::uninit();
				ptr::copy_nonoverlapping(
					data_ptr,
					maybe_hdr.as_mut_ptr() as *mut u8,
					mem::size_of::<if_msghdr_partial>(),
				);
				maybe_hdr.assume_init()
			};
			debug_assert!(hdr.ifm_msglen as usize <= self.data.len() + self.position);

			self.position += hdr.ifm_msglen as usize;

			if libc::c_int::from(hdr.ifm_type) == libc::RTM_IFINFO2 {
				let hdr = unsafe {
					let mut maybe_hdr = mem::MaybeUninit::<if_msghdr2>::uninit();
					ptr::copy_nonoverlapping(
						data_ptr,
						maybe_hdr.as_mut_ptr() as *mut u8,
						mem::size_of::<if_msghdr2>(),
					);
					maybe_hdr.assume_init()
				};

				// Just in case to be sure that copying worked properly
				debug_assert!(libc::c_int::from(hdr.ifm_type) == libc::RTM_IFINFO2);

				return Some(hdr);
			} else {
				continue;
			}
		}
	}
}

#[repr(C)]
struct if_data64 {
	pub ifi_type: libc::c_uchar,
	pub ifi_typelen: libc::c_uchar,
	pub ifi_physical: libc::c_uchar,
	pub ifi_addrlen: libc::c_uchar,
	pub ifi_hdrlen: libc::c_uchar,
	pub ifi_recvquota: libc::c_uchar,
	pub ifi_xmitquota: libc::c_uchar,
	pub ifi_unused1: libc::c_uchar,
	pub ifi_mtu: u32,
	pub ifi_metric: u32,
	pub ifi_baudrate: u64,
	pub ifi_ipackets: u64,
	pub ifi_ierrors: u64,
	pub ifi_opackets: u64,
	pub ifi_oerrors: u64,
	pub ifi_collisions: u64,
	pub ifi_ibytes: u64,
	pub ifi_obytes: u64,
	pub ifi_imcasts: u64,
	pub ifi_omcasts: u64,
	pub ifi_iqdrops: u64,
	pub ifi_noproto: u64,
	pub ifi_recvtiming: u32,
	pub ifi_xmittiming: u32,
	pub ifi_lastchange: libc::timeval,
}

#[repr(C)]
struct if_msghdr2 {
	pub ifm_msglen: libc::c_ushort,
	pub ifm_version: libc::c_uchar,
	pub ifm_type: libc::c_uchar,
	pub ifm_addrs: libc::c_int,
	pub ifm_flags: libc::c_int,
	pub ifm_index: libc::c_ushort,
	pub ifm_snd_len: libc::c_int,
	pub ifm_snd_maxlen: libc::c_int,
	pub ifm_snd_drops: libc::c_int,
	pub ifm_timer: libc::c_int,
	pub ifm_data: if_data64,
}

#[repr(C)]
struct if_msghdr_partial {
	pub ifm_msglen: libc::c_ushort,
	pub ifm_version: libc::c_uchar,
	pub ifm_type: libc::c_uchar,
}

unsafe fn net_pf_route() -> io::Result<Routes> {
	let mut name: [libc::c_int; 6] = [libc::CTL_NET, libc::PF_ROUTE, 0, 0, libc::NET_RT_IFLIST2, 0];
	let mut length: libc::size_t = 0;

	let result = libc::sysctl(
		name.as_mut_ptr(),
		6,
		ptr::null_mut(),
		&mut length,
		ptr::null_mut(),
		0,
	);

	if result != 0 {
		return Err(io::Error::last_os_error());
	}

	let mut data: Vec<u8> = Vec::with_capacity(length);
	let result = libc::sysctl(
		name.as_mut_ptr(),
		6,
		data.as_mut_ptr() as *mut libc::c_void,
		&mut length,
		ptr::null_mut(),
		0,
	);

	if result == 0 {
		data.set_len(length);
		Ok(Routes { position: 0, data })
	} else {
		Err(io::Error::last_os_error())
	}
}

impl From<if_msghdr2> for NetIoCounters {
	fn from(data: if_msghdr2) -> Self {
		NetIoCounters {
			bytes_sent: data.ifm_data.ifi_obytes,
			bytes_recv: data.ifm_data.ifi_ibytes,
			packets_sent: data.ifm_data.ifi_opackets,
			packets_recv: data.ifm_data.ifi_ipackets,
			err_in: data.ifm_data.ifi_ierrors,
			err_out: data.ifm_data.ifi_oerrors,
			drop_in: data.ifm_data.ifi_iqdrops,
			drop_out: 0, // TODO
		}
	}
}

pub(crate) fn net_io_counters_pernic() -> Result<HashMap<String, NetIoCounters>> {
	let interfaces = unsafe { net_pf_route() };
	interfaces?
		.into_iter()
		.map(|msg: if_msghdr2| {
			let mut name: [u8; libc::IF_NAMESIZE] = [0; libc::IF_NAMESIZE];
			let result = unsafe {
				libc::if_indextoname(msg.ifm_index.into(), name.as_mut_ptr() as *mut libc::c_char)
			};
			if result.is_null() {
				return Err(io::Error::last_os_error());
			}
			let first_nul = name.iter().position(|c| *c == b'\0').unwrap_or(0);
			let name = String::from_utf8_lossy(&name[..first_nul]).to_string();

			Ok((name, NetIoCounters::from(msg)))
		})
		.map(|result| result.map_err(Error::from))
		.collect()
}
