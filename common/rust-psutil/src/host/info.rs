#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use platforms::target::{Arch, OS};

/// Not found in Python psutil.
#[cfg_attr(feature = "serde", serde(crate = "renamed_serde"))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug)]
pub struct Info {
	pub(crate) operating_system: OS,
	pub(crate) release: String,
	pub(crate) version: String,
	pub(crate) hostname: String,
	pub(crate) architecture: Arch,
}

impl Info {
	pub fn operating_system(&self) -> OS {
		self.operating_system
	}

	pub fn release(&self) -> &str {
		&self.release
	}

	pub fn version(&self) -> &str {
		&self.version
	}

	pub fn hostname(&self) -> &str {
		&self.hostname
	}

	pub fn architecture(&self) -> Arch {
		self.architecture
	}
}
