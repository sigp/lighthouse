use std::convert::TryFrom;
use std::str::FromStr;

use crate::process::Status;
use crate::ParseStatusError;

/// Returns a Status based on a status character from `/proc/[pid]/stat`.
///
/// See [array.c:115] and [proc(5)].
///
/// [array.c:115]: https://github.com/torvalds/linux/blob/master/fs/proc/array.c#L115
/// [proc(5)]: http://man7.org/linux/man-pages/man5/proc.5.html
impl TryFrom<char> for Status {
	type Error = ParseStatusError;

	fn try_from(value: char) -> Result<Self, Self::Error> {
		match value {
			'R' => Ok(Status::Running),
			'S' => Ok(Status::Sleeping),
			'D' => Ok(Status::Waiting),
			'Z' => Ok(Status::Zombie),
			'T' => Ok(Status::Stopped),
			't' => Ok(Status::TracingStop),
			'X' | 'x' => Ok(Status::Dead),
			'K' => Ok(Status::WakeKill),
			'W' => Ok(Status::Waking),
			'P' => Ok(Status::Parked),
			'I' => Ok(Status::Idle),
			_ => Err(ParseStatusError::IncorrectChar {
				contents: value.to_string(),
			}),
		}
	}
}

impl FromStr for Status {
	type Err = ParseStatusError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if s.len() != 1 {
			return Err(ParseStatusError::IncorrectLength {
				contents: s.to_string(),
			});
		}

		Status::try_from(s.chars().next().unwrap())
	}
}

impl ToString for Status {
	fn to_string(&self) -> String {
		match *self {
			Status::Running => "R",
			Status::Sleeping => "S",
			Status::DiskSleep => "D",
			Status::Zombie => "Z",
			Status::Stopped => "T",
			Status::TracingStop => "t",
			Status::Dead => "X",
			Status::WakeKill => "K",
			Status::Waking => "W",
			Status::Parked => "P",
			Status::Idle => "I",
			_ => "",
		}
		.to_string()
	}
}
