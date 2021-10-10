#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::common::TcpConnectionStatus;
use crate::{Fd, Pid};

#[cfg_attr(feature = "serde", serde(crate = "renamed_serde"))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NetConnection {}

impl NetConnection {
	pub fn fd(&self) -> Option<Fd> {
		todo!()
	}

	// TODO: return type
	pub fn family(&self) {
		todo!()
	}

	// TODO: return type
	/// Renamed from `type` in Python psutil.
	pub fn address_type(&self) {
		todo!()
	}

	// TODO: return type
	/// Renamed from `laddr` in Python psutil.
	pub fn local_addr(&self) {
		todo!()
	}

	// TODO: return type
	/// Renamed from `raddr` in Python psutil.
	pub fn remote_addr(&self) {
		todo!()
	}

	pub fn status(&self) -> Option<TcpConnectionStatus> {
		todo!()
	}

	pub fn pid(&self) -> Option<Pid> {
		todo!()
	}
}
