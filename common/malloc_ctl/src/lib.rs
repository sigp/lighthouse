pub mod trimmer_thread;

pub use std::os::raw::{c_int, c_ulong};

/// A default value to be provided to `malloc_trim`.
///
/// Value sourced from:
///
/// - https://man7.org/linux/man-pages/man3/mallopt.3.html
pub const DEFAULT_TRIM: c_ulong = 1_024 * 128;

/// Used to configure malloc internals.
///
/// Source:
///
/// https://github.com/lattera/glibc/blob/895ef79e04a953cac1493863bcae29ad85657ee1/malloc/malloc.h#L123
const M_ARENA_MAX: c_int = -8;

mod ffi {
    extern "C" {
        pub fn malloc_trim(__pad: std::os::raw::c_ulong) -> ::std::os::raw::c_int;
    }

    extern "C" {
        pub fn malloc_stats();
    }

    extern "C" {
        pub fn mallopt(
            __param: ::std::os::raw::c_int,
            __val: ::std::os::raw::c_int,
        ) -> ::std::os::raw::c_int;
    }
}

fn into_result(result: c_int) -> Result<(), c_int> {
    if result == 1 {
        Ok(())
    } else {
        Err(result)
    }
}

pub fn malloc_arena_max(num_arenas: c_int) -> Result<(), c_int> {
    unsafe { into_result(ffi::mallopt(M_ARENA_MAX, num_arenas)) }
}

/// Calls `malloc_trim(0)`, freeing up available memory at the expense of CPU time and arena
/// locking.
///
/// ## Resources
///
/// - https://man7.org/linux/man-pages/man3/malloc_trim.3.html
pub fn malloc_trim(pad: c_ulong) -> Result<(), c_int> {
    unsafe { into_result(ffi::malloc_trim(pad)) }
}

/// Calls `malloc_stats`, printing the output to stderr.
///
/// ## Resources
///
/// - https://man7.org/linux/man-pages/man3/malloc_stats.3.html
pub fn eprintln_malloc_stats() {
    unsafe { ffi::malloc_stats() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malloc_arena_max_does_not_panic() {
        malloc_arena_max(1).unwrap()
    }

    #[test]
    fn malloc_default_trim_does_not_panic() {
        malloc_trim(DEFAULT_TRIM).unwrap()
    }

    /// Unfortunately this test will print into the test results, even on success. I don't know any
    /// way to avoid this.
    #[test]
    fn eprintln_malloc_stats_does_not_panic() {
        eprintln_malloc_stats()
    }
}
