#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::FloatCount;

#[cfg_attr(feature = "serde", serde(crate = "renamed_serde"))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug)]
pub struct LoadAvg {
	/// Number of jobs in the run queue averaged over 1 minute.
	pub one: FloatCount,

	/// Number of jobs in the run queue averaged over 5 minute.
	pub five: FloatCount,

	/// Number of jobs in the run queue averaged over 15 minute.
	pub fifteen: FloatCount,
}
