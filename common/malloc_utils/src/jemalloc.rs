//! Set the allocator to `jemalloc`.
//!
//! Due to `jemalloc` requiring configuration at compile time or immediately upon runtime
//! initialisation it is configured via a Cargo config file in `.cargo/config.toml`.
//!
//! The `jemalloc` tuning can be overriden by:
//!
//! A) `JEMALLOC_SYS_WITH_MALLOC_CONF` at compile-time.
//! B) `_RJEM_MALLOC_CONF` at runtime.

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;
