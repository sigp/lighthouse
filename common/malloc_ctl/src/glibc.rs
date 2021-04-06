use std::env;
/// Contains functions for tuning and controlling "The GNU Allocator", included in the `glibc`
/// library.
///
/// https://www.gnu.org/software/libc/manual/html_node/The-GNU-Allocator.html
///
/// These functions are generally only suitable for Linux systems.
use std::os::raw::{c_int, c_ulong};
use std::thread;
use std::time::Duration;

/// The value to be provided to `malloc_trim`.
///
/// Value sourced from:
///
/// - https://man7.org/linux/man-pages/man3/mallopt.3.html
const OPTIMAL_TRIM: c_ulong = 1_024 * 128;

/// The value to be provided to `malloc_mmap_threshold`.
///
/// Value chosen so that it will store the values of the validators tree hash cache.
const OPTIMAL_MMAP_THRESHOLD: c_int = 2 * 1_024 * 1_024;

/// The maximum number of arenas allowed to be created by malloc.
const OPTIMAL_ARENA_MAX: c_int = 1;

/// Constants used to configure malloc internals.
///
/// Source:
///
/// https://github.com/lattera/glibc/blob/895ef79e04a953cac1493863bcae29ad85657ee1/malloc/malloc.h#L115-L123
const M_MMAP_THRESHOLD: c_int = -4;
const M_ARENA_MAX: c_int = -8;

/// The default interval between calls to `spawn_trimmer_thread`.
const OPTIMAL_TRIM_INTERVAL: Duration = Duration::from_secs(60);

/// Environment variables used to configure malloc.
///
/// Source:
///
/// https://man7.org/linux/man-pages/man3/mallopt.3.html
const ENV_VAR_ARENA_MAX: &str = "MALLOC_ARENA_MAX";
const ENV_VAR_MMAP_THRESHOLD: &str = "MALLOC_MMAP_THRESHOLD_";

pub fn configure_glibc_malloc() -> Result<(), String> {
    if !env_var_present(ENV_VAR_ARENA_MAX) {
        if let Err(e) = malloc_arena_max(OPTIMAL_ARENA_MAX) {
            return Err(format!("failed (code {}) to set malloc max arena count", e));
        }
    }

    if !env_var_present(ENV_VAR_MMAP_THRESHOLD) {
        if let Err(e) = malloc_mmap_threshold(OPTIMAL_MMAP_THRESHOLD) {
            return Err(format!("failed (code {}) to set malloc mmap threshold", e));
        }
    }

    spawn_trimmer_thread(OPTIMAL_TRIM_INTERVAL, OPTIMAL_TRIM);

    Ok(())
}

/// Returns `true` if an environment variable is present.
fn env_var_present(name: &str) -> bool {
    env::var(name) != Err(env::VarError::NotPresent)
}

/// Spawns a thread which will call `crate::malloc_trim(trim)`, sleeping `interval` between each
/// call.
///
/// The function will not call `malloc_trim` on start, the first call will happen after `interval`
/// has elapsed.
fn spawn_trimmer_thread(interval: Duration, trim: c_ulong) -> thread::JoinHandle<()> {
    thread::spawn(move || loop {
        thread::sleep(interval);

        if let Err(e) = malloc_trim(trim) {
            eprintln!("malloc_trim failed with {}", e);
        }
    })
}

/// Uses `mallopt` to set the `M_ARENA_MAX` value, specifying the number of memory arenas to be
/// created by malloc.
///
/// Generally speaking, a smaller arena count reduces memory fragmentation at the cost of memory contention
/// between threads.
///
/// ## Resources
///
/// - https://man7.org/linux/man-pages/man3/mallopt.3.html
fn malloc_arena_max(num_arenas: c_int) -> Result<(), c_int> {
    unsafe { into_result(ffi::mallopt(M_ARENA_MAX, num_arenas)) }
}

/// Uses `mallopt` to set the `M_MMAP_THRESHOLD` value, specifying the threshold where objects of this
/// size or larger are allocated via an `mmap`.
///
/// ## Resources
///
/// - https://man7.org/linux/man-pages/man3/mallopt.3.html
fn malloc_mmap_threshold(num_arenas: c_int) -> Result<(), c_int> {
    unsafe { into_result(ffi::mallopt(M_MMAP_THRESHOLD, num_arenas)) }
}

/// The outcome of calling `malloc_trim`.
enum TrimOutcome {
    /// Memory was actually released back to the system.
    MemoryFreed,
    /// It was not possible to release any memory.
    NoMemoryFreed,
}

/// Calls `malloc_trim(0)`, freeing up available memory at the expense of CPU time and arena
/// locking.
///
/// ## Resources
///
/// - https://man7.org/linux/man-pages/man3/malloc_trim.3.html
fn malloc_trim(pad: c_ulong) -> Result<TrimOutcome, c_int> {
    unsafe {
        match ffi::malloc_trim(pad) {
            0 => Ok(TrimOutcome::NoMemoryFreed),
            1 => Ok(TrimOutcome::MemoryFreed),
            other => Err(other),
        }
    }
}

/// Calls `malloc_stats`, printing the output to stderr.
///
/// ## Resources
///
/// - https://man7.org/linux/man-pages/man3/malloc_stats.3.html
pub fn eprintln_malloc_stats() {
    unsafe { ffi::malloc_stats() }
}

mod ffi {
    /// See: https://man7.org/linux/man-pages/man3/malloc_trim.3.html
    extern "C" {
        pub fn malloc_trim(__pad: std::os::raw::c_ulong) -> ::std::os::raw::c_int;
    }

    /// See: https://man7.org/linux/man-pages/man3/malloc_stats.3.html
    extern "C" {
        pub fn malloc_stats();
    }

    /// See: https://man7.org/linux/man-pages/man3/mallopt.3.html
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malloc_arena_max_does_not_panic() {
        malloc_arena_max(1).unwrap();
    }

    #[test]
    fn malloc_default_trim_does_not_panic() {
        malloc_trim(OPTIMAL_TRIM).unwrap();
    }

    /// Unfortunately this test will print into the test results, even on success. I don't know any
    /// way to avoid this.
    #[test]
    fn eprintln_malloc_stats_does_not_panic() {
        eprintln_malloc_stats();
    }
}
