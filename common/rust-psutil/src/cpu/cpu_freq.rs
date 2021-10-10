#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::Mhz;

#[cfg_attr(feature = "serde", serde(crate = "renamed_serde"))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CpuFreq {}

impl CpuFreq {
	pub fn current(&self) -> Mhz {
		todo!()
	}

	pub fn min(&self) -> Mhz {
		todo!()
	}

	pub fn max(&self) -> Mhz {
		todo!()
	}
}
