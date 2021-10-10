#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use std::net::IpAddr;

#[cfg_attr(feature = "serde", serde(crate = "renamed_serde"))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NetIfAddr {}

impl NetIfAddr {
	// TODO: return type
	pub fn family(&self) {
		todo!()
	}

	pub fn address(&self) -> IpAddr {
		todo!()
	}

	pub fn netmask(&self) -> Option<IpAddr> {
		todo!()
	}

	pub fn broadcast(&self) -> Option<IpAddr> {
		todo!()
	}

	pub fn ptp(&self) -> Option<IpAddr> {
		todo!()
	}
}
