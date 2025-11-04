//! Provides utilities for configuring the system allocator.
//!
//! ## Conditional Compilation
//!
//! This crate can be compiled with different feature flags to support different allocators:
//!
//! - Jemalloc, via the `jemalloc` feature.
//! - GNU malloc, if no features are set and the system supports it.
//! - The system allocator, if no features are set and the allocator is not GNU malloc.
//!
//! It is assumed that if Jemalloc is not in use, and the following two statements are correct then
//! we should expect to configure `glibc`:
//!
//! - `target_os = linux`
//! - `target_env != musl`
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

#[cfg(all(
    any(feature = "sysmalloc", not(feature = "jemalloc")),
    target_os = "linux",
    not(target_env = "musl")
))]
pub mod glibc;

#[cfg(all(unix, not(feature = "sysmalloc"), feature = "jemalloc"))]
pub mod jemalloc;

pub use interface::*;

// Glibc malloc is the default on non-musl Linux if the sysmalloc feature is enabled, or jemalloc
// is disabled.
#[cfg(all(
    any(feature = "sysmalloc", not(feature = "jemalloc")),
    target_os = "linux",
    not(target_env = "musl")
))]
mod interface {
    pub use crate::glibc::configure_glibc_malloc as configure_memory_allocator;
    pub use crate::glibc::scrape_mallinfo_metrics as scrape_allocator_metrics;

    pub fn allocator_name() -> String {
        "glibc".to_string()
    }
}

// Jemalloc is the default on UNIX (including musl) unless the sysmalloc feature is enabled.
#[cfg(all(unix, not(feature = "sysmalloc"), feature = "jemalloc"))]
mod interface {
    #[allow(dead_code)]
    pub fn configure_memory_allocator() -> Result<(), String> {
        Ok(())
    }

    pub use crate::jemalloc::scrape_jemalloc_metrics as scrape_allocator_metrics;

    pub fn allocator_name() -> String {
        match crate::jemalloc::page_size() {
            Ok(page_size) => format!("jemalloc ({}K)", page_size / 1024),
            Err(e) => format!("jemalloc (error: {e:?})"),
        }
    }
}

#[cfg(any(
    not(unix),
    all(
        any(feature = "sysmalloc", not(feature = "jemalloc")),
        any(not(target_os = "linux"), target_env = "musl")
    )
))]
mod interface {
    #[allow(dead_code, clippy::unnecessary_wraps)]
    pub fn configure_memory_allocator() -> Result<(), String> {
        Ok(())
    }

    #[allow(dead_code)]
    pub fn scrape_allocator_metrics() {}

    pub fn allocator_name() -> String {
        "system".to_string()
    }
}
