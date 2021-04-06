mod glibc;

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(not(target_os = "linux"))]
pub use not_linux::*;

pub mod linux {
    pub use crate::glibc::configure_glibc_malloc as configure_memory_allocator;
    pub use crate::glibc::eprintln_malloc_stats as eprintln_allocator_stats;
}

pub mod not_linux {
    #[allow(dead_code, clippy::unnecessary_wraps)]
    pub fn configure_memory_allocator() -> Result<(), String> {
        Ok(())
    }

    #[allow(dead_code)]
    pub fn eprintln_allocator_stats() {}
}
