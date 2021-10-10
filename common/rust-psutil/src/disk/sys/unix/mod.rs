mod disk_usage;
#[cfg(not(target_os = "linux"))]
mod partitions;

pub use disk_usage::*;
#[cfg(not(target_os = "linux"))]
pub use partitions::*;
