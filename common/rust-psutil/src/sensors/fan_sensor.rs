#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::Rpm;

#[cfg_attr(feature = "serde", serde(crate = "renamed_serde"))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FanSensor {
	pub(crate) _label: String,
	pub(crate) _current: Rpm,
}
