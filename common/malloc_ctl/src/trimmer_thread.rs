use crate::{c_ulong, malloc_trim};
use std::thread;
use std::time::Duration;

pub const DEFAULT_TRIM_INTERVAL: Duration = Duration::from_secs(60);

/// Spawns a thread which will call `crate::malloc_trim(trim)`, sleeping `interval` between each
/// call.
///
/// The function will not call `malloc_trim` on start, the first call will happen after `interval`
/// has elapsed.
pub fn spawn_trimmer_thread(interval: Duration, trim: c_ulong) -> thread::JoinHandle<()> {
    thread::spawn(move || loop {
        thread::sleep(interval);

        if let Err(e) = malloc_trim(trim) {
            eprintln!("malloc_trim failed with {}", e);
        }
    })
}
