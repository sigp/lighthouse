#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::Bytes;

#[cfg_attr(feature = "serde", serde(crate = "renamed_serde"))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Duplex {
	Full,
	Half,
	Unknown,
}

#[cfg_attr(feature = "serde", serde(crate = "renamed_serde"))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NetIfStats {}

impl NetIfStats {
	pub fn is_up(&self) -> bool {
		todo!()
	}

	pub fn duplex(&self) -> Duplex {
		todo!()
	}

	pub fn speed(&self) -> Bytes {
		todo!()
	}

	pub fn mtu(&self) -> Bytes {
		todo!()
	}
}
