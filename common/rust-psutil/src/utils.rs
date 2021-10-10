use std::time::Duration;

use crate::Percent;

// TODO: switch this to nightly div_duration_f64
pub(crate) fn div_duration_f64(lhs: Duration, rhs: Duration) -> f64 {
	lhs.as_secs_f64() / rhs.as_secs_f64()
}

pub(crate) fn duration_percent(lhs: Duration, rhs: Duration) -> Percent {
	(div_duration_f64(lhs, rhs) * 100.0) as f32
}

pub(crate) fn u64_percent(lhs: u64, rhs: u64) -> Percent {
	((lhs as f64 / rhs as f64) * 100.0) as f32
}
