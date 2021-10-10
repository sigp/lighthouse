#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub type Fd = u32;
pub type Pid = u32;

pub type Count = u64;
pub type Bytes = Count;
pub type Rpm = Count;

pub type Percent = f32;

pub type FloatCount = f64;
pub type Degrees = FloatCount;
pub type Mhz = FloatCount;

#[cfg_attr(feature = "serde", serde(crate = "renamed_serde"))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone)]
pub struct Temperature {
	celsius: Degrees,
}

impl Temperature {
	pub fn new(celsius: Degrees) -> Temperature {
		Temperature { celsius }
	}

	pub fn celsius(&self) -> Degrees {
		self.celsius
	}

	#[allow(clippy::unnecessary_cast)]
	pub fn fahrenheit(&self) -> Degrees {
		(self.celsius * (9 as Degrees / 5 as Degrees)) + 32 as Degrees
	}
}
