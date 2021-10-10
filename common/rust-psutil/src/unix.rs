// https://github.com/heim-rs/heim/blob/master/heim-common/src/sys/unix.rs

use nix::unistd;
use once_cell::sync::Lazy;

use crate::{Bytes, FloatCount};

pub(crate) static TICKS_PER_SECOND: Lazy<FloatCount> = Lazy::new(|| {
	unistd::sysconf(unistd::SysconfVar::CLK_TCK)
		.unwrap()
		.unwrap() as FloatCount
});

pub(crate) static PAGE_SIZE: Lazy<Bytes> = Lazy::new(|| {
	unistd::sysconf(unistd::SysconfVar::PAGE_SIZE)
		.unwrap()
		.unwrap() as Bytes
});
