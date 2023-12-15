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
    target_os = "linux",
    not(target_env = "musl"),
    not(feature = "jemalloc")
))]
mod glibc;

#[cfg(feature = "jemalloc")]
mod jemalloc;

pub use interface::*;

#[cfg(all(
    target_os = "linux",
    not(target_env = "musl"),
    not(feature = "jemalloc")
))]
mod interface {
    pub use crate::glibc::configure_glibc_malloc as configure_memory_allocator;
    pub use crate::glibc::scrape_mallinfo_metrics as scrape_allocator_metrics;

    #[allow(dead_code)]
    pub use super::prof_dump_unsupported as prof_dump;
}

#[cfg(feature = "jemalloc")]
mod interface {
    #[allow(dead_code)]
    pub fn configure_memory_allocator() -> Result<(), String> {
        Ok(())
    }

    pub use crate::jemalloc::scrape_jemalloc_metrics as scrape_allocator_metrics;

    #[cfg(not(feature = "jemalloc_profiling"))]
    pub use super::prof_dump_unsupported as prof_dump;
    #[cfg(feature = "jemalloc_profiling")]
    pub use crate::jemalloc::prof_dump;

    pub use crate::jemalloc::prof_active;
}

#[cfg(all(
    any(not(target_os = "linux"), target_env = "musl"),
    not(feature = "jemalloc")
))]
mod interface {
    #[allow(dead_code, clippy::unnecessary_wraps)]
    pub fn configure_memory_allocator() -> Result<(), String> {
        Ok(())
    }

    #[allow(dead_code)]
    pub fn scrape_allocator_metrics() {}

    #[allow(dead_code)]
    pub use super::prof_dump_unsupported as prof_dump;
}

#[allow(dead_code)]
pub fn prof_dump_unsupported(_: &str) -> Result<(), String> {
    Err(
        "Profile dumps are only supported when Lighthouse is built for Linux \
        using the `jemalloc` and `jemalloc_profiling` features."
            .to_string(),
    )
}
