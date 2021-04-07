//! Provides utilities for configuring the system allocator.
//!
//! ## Conditional Compilation
//!
//! Presently, only configuration for "The GNU Allocator" from `glibc` is supported. All other
//! allocators are ignored.
//!
//! It is assumed that if the following two statements are correct, then we should expect to
//! configure `glibc`:
//!
//! - `target_os = linux`
//! - `target_env != musl`
//!
//! In all other cases this library will not attempt to do anything (i.e., all functions are no-ops).
//!
//! ## Notes
//!
//! It's not clear how to precisely determine what the underlying allocator is. The efforts at
//! detecting `glibc` are best-effort. If this crate throws errors about undefined external
//! functions, then try to compile with the `not_glibc_interface` module.

mod glibc;

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
pub use glibc_interface::*;

#[cfg(any(not(target_os = "linux"), target_env = "musl"))]
pub use not_glibc_interface::*;

pub mod glibc_interface {
    pub use crate::glibc::configure_glibc_malloc as configure_memory_allocator;
    pub use crate::glibc::eprintln_malloc_stats as eprintln_allocator_stats;
}

pub mod not_glibc_interface {
    #[allow(dead_code, clippy::unnecessary_wraps)]
    pub fn configure_memory_allocator() -> Result<(), String> {
        Ok(())
    }

    #[allow(dead_code)]
    pub fn eprintln_allocator_stats() {}
}
