#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::Temperature;

#[cfg_attr(feature = "serde", serde(crate = "renamed_serde"))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct TemperatureSensor {
	pub(crate) unit: String,
	pub(crate) label: Option<String>,
	pub(crate) current: Temperature,
	pub(crate) max: Option<Temperature>,
	pub(crate) crit: Option<Temperature>,
}

impl TemperatureSensor {
	/// Returns sensor unit name.
	pub fn unit(&self) -> &str {
		&self.unit
	}

	/// Returns sensor label.
	pub fn label(&self) -> Option<&str> {
		self.label.as_deref()
	}

	/// Returns current temperature reported by sensor.
	pub fn current(&self) -> &Temperature {
		&self.current
	}

	/// Returns high trip point for sensor if available.
	pub fn high(&self) -> Option<&Temperature> {
		self.max.as_ref()
	}

	/// Returns critical trip point for sensor if available.
	pub fn critical(&self) -> Option<&Temperature> {
		self.crit.as_ref()
	}
}
