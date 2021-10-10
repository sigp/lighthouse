#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use std::time::SystemTime;

use crate::Pid;

#[cfg_attr(feature = "serde", serde(crate = "renamed_serde"))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct User {}

impl User {
	pub fn user(&self) -> &str {
		todo!()
	}

	pub fn terminal(&self) -> Option<&str> {
		todo!()
	}

	pub fn host(&self) -> Option<&str> {
		todo!()
	}

	pub fn started(&self) -> SystemTime {
		todo!()
	}

	pub fn pid(&self) -> Option<Pid> {
		todo!()
	}
}
