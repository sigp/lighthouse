cfg_if::cfg_if! {
	if #[cfg(target_os = "linux")] {
		mod linux;
		pub use linux::*;
	}
}

cfg_if::cfg_if! {
	if #[cfg(target_family = "unix")] {
		mod unix;
		pub use unix::*;
	}
}
