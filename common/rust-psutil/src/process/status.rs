#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Possible statuses for a process.
#[cfg_attr(feature = "serde", serde(crate = "renamed_serde"))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, Debug)]
pub enum Status {
	/// (R)
	Running,

	/// (S) Sleeping in an interruptible wait
	Sleeping,

	/// (D) Waiting in uninterruptible disk sleep
	DiskSleep,

	/// (T) Stopped (on a signal)
	///
	/// Or before Linux 2.6.33, trace stopped
	Stopped,

	/// (t) (Linux 2.6.33 onward)
	TracingStop,

	/// (Z)
	Zombie,

	/// (X)
	Dead,

	/// (Linux 2.6.33 to 3.13 only)
	WakeKill,

	/// (Linux 2.6.33 to 3.13 only)
	Waking,

	/// (P) (Linux 3.9 to 3.13 only)
	Parked,

	/// (I) (Linux, macOS, FreeBSD)
	Idle,

	/// (FreeBSD)
	Locked,

	/// (FreeBSD)
	Waiting,

	/// (NetBSD)
	Suspended,
}
