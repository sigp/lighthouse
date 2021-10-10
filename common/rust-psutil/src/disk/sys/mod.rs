cfg_if::cfg_if! {
	if #[cfg(target_os = "linux")] {
		mod linux;
		pub use linux::*;
	} else if #[cfg(target_os = "macos")] {
		mod macos;
		#[allow(unused_imports)]
		pub use macos::*;
	}
}

cfg_if::cfg_if! {
	if #[cfg(target_family = "unix")] {
		mod unix;
		pub use unix::*;
	}
}
