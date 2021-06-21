//! Provides utilities for configuring the system allocator.
//!
//! ## Conditional Compilation
//!
//! Presently, only configuration for "The GNU Allocator" from `glibc` is supported. All other
//! allocators are ignored.
//!
//! It is assumed that if the following two statements are correct then we should expect to
//! configure `glibc`:
//!
//! - `target_os = linux`
//! - `target_env != musl`
//!
//! In all other cases this library will not attempt to do anything (i.e., all functions are
//! no-ops).
//!
//! If the above conditions are fulfilled but `glibc` still isn't present at runtime then a panic
//! may be triggered. It is understood that there's no way to be certain that a compatible `glibc`
//! is present: https://github.com/rust-lang/rust/issues/33244.
//!
//! ## Notes
//!
//! It's not clear how to precisely determine what the underlying allocator is. The efforts at
//! detecting `glibc` are best-effort. If this crate throws errors about undefined external
//! functions, then try to compile with the `not_glibc_interface` module.

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
mod glibc;

pub use interface::*;

#[cfg(all(target_os = "linux", not(target_env = "musl")))]
mod interface {
    pub use crate::glibc::configure_glibc_malloc as configure_memory_allocator;
    pub use crate::glibc::scrape_mallinfo_metrics as scrape_allocator_metrics;
}

#[cfg(any(not(target_os = "linux"), target_env = "musl"))]
mod interface {
    #[allow(dead_code, clippy::unnecessary_wraps)]
    pub fn configure_memory_allocator() -> Result<(), String> {
        Ok(())
    }

    #[allow(dead_code)]
    pub fn scrape_allocator_metrics() {}
}
