//! Provides utilities for configuring the system allocator.
//!
//! ## Conditional Compilation
//!
//! This crate can be compiled with different feature flags to support different allocators:
//!
//! - Jemalloc, via the `jemalloc` feature.
//! - mimalloc, via the `mimalloc` feature.
//! - tcmalloc, via the `tcmalloc` feature.
//! - GNU malloc, if no features are set and the system supports it.
//! - The system allocator, if no features are set and the allocator is not GNU malloc.
//!
//! When multiple allocator features are enabled (e.g. because `jemalloc` is hardcoded in the
//! binary dependencies), the priority order is: mimalloc > tcmalloc > jemalloc > glibc > system.
//!
//! It is assumed that if no allocator feature is in use, and the following two statements are
//! correct then we should expect to configure `glibc`:
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

// Ensure mimalloc and tcmalloc are not both enabled.
// Note: jemalloc + mimalloc/tcmalloc is allowed because jemalloc is hardcoded in the lighthouse
// and lcli binary dependencies. mimalloc/tcmalloc override jemalloc via cfg guards, matching the
// existing sysmalloc override pattern.
#[cfg(all(feature = "mimalloc", feature = "tcmalloc"))]
compile_error!("Cannot enable both `mimalloc` and `tcmalloc` allocator features");

// mimalloc is compiled on unix, tcmalloc on linux only. Fail loudly rather than
// silently falling back to the system allocator.
#[cfg(all(not(unix), feature = "mimalloc"))]
compile_error!("`mimalloc` feature is only supported on unix targets");

#[cfg(all(not(target_os = "linux"), feature = "tcmalloc"))]
compile_error!("`tcmalloc` feature is only supported on Linux targets");

#[cfg(all(
    any(
        feature = "sysmalloc",
        not(any(feature = "jemalloc", feature = "mimalloc", feature = "tcmalloc"))
    ),
    target_os = "linux",
    not(target_env = "musl")
))]
pub mod glibc;

#[cfg(all(
    unix,
    not(feature = "sysmalloc"),
    not(feature = "mimalloc"),
    not(feature = "tcmalloc"),
    feature = "jemalloc"
))]
pub mod jemalloc;

#[cfg(all(unix, not(feature = "sysmalloc"), feature = "mimalloc"))]
pub mod mimalloc_alloc;

#[cfg(all(target_os = "linux", not(feature = "sysmalloc"), feature = "tcmalloc"))]
pub mod tcmalloc_alloc;

pub use interface::*;

// Glibc malloc is the default on non-musl Linux when no allocator feature is set, or when
// sysmalloc is explicitly requested.
#[cfg(all(
    any(
        feature = "sysmalloc",
        not(any(feature = "jemalloc", feature = "mimalloc", feature = "tcmalloc"))
    ),
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

// Jemalloc is the default on UNIX (including musl) unless overridden by sysmalloc, mimalloc, or
// tcmalloc.
#[cfg(all(
    unix,
    not(feature = "sysmalloc"),
    not(feature = "mimalloc"),
    not(feature = "tcmalloc"),
    feature = "jemalloc"
))]
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

// mimalloc allocator.
#[cfg(all(unix, not(feature = "sysmalloc"), feature = "mimalloc"))]
mod interface {
    #[allow(dead_code)]
    pub fn configure_memory_allocator() -> Result<(), String> {
        Ok(())
    }

    pub use crate::mimalloc_alloc::scrape_mimalloc_metrics as scrape_allocator_metrics;

    pub fn allocator_name() -> String {
        "mimalloc".to_string()
    }
}

// tcmalloc allocator (via modern Google TCMalloc).
#[cfg(all(target_os = "linux", not(feature = "sysmalloc"), feature = "tcmalloc"))]
mod interface {
    #[allow(dead_code)]
    pub fn configure_memory_allocator() -> Result<(), String> {
        Ok(())
    }

    pub use crate::tcmalloc_alloc::scrape_tcmalloc_metrics as scrape_allocator_metrics;

    pub fn allocator_name() -> String {
        "tcmalloc".to_string()
    }
}

// System allocator fallback for platforms where no allocator feature applies.
#[cfg(any(
    not(unix),
    all(
        any(
            feature = "sysmalloc",
            not(any(feature = "jemalloc", feature = "mimalloc", feature = "tcmalloc"))
        ),
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
