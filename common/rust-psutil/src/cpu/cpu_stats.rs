#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::Count;

#[cfg_attr(feature = "serde", serde(crate = "renamed_serde"))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CpuStats {}

impl CpuStats {
	pub fn ctx_switches(&self) -> Count {
		todo!()
	}

	pub fn interrupts(&self) -> Count {
		todo!()
	}

	pub fn soft_interrupts(&self) -> Count {
		todo!()
	}

	pub fn syscalls(&self) -> Count {
		todo!()
	}
}
