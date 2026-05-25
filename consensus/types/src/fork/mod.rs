mod fork;
mod fork_context;
mod fork_data;
mod fork_macros;
mod fork_name;
mod fork_version_decode;

pub use crate::{map_fork_name, map_fork_name_with};
pub use fork::Fork;
pub use fork_context::{ForkContext, HardFork};
pub use fork_data::ForkData;
pub use fork_name::{ForkName, InconsistentFork};
pub use fork_version_decode::ForkVersionDecode;

pub type ForkVersion = [u8; 4];
