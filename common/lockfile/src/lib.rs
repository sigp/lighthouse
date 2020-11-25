use fs2::FileExt;
use std::fs::{self, File};
use std::io;
use std::path::PathBuf;

/// Cross-platform file lock that auto-deletes on drop.
///
/// This lockfile uses OS locking primitives (`flock` on Unix, `LockFile` on Windows), and will
/// only fail if locked by another process. I.e. if the file being locked already exists but isn't
/// locked, then it can still be locked. This is relevant if an ungraceful shutdown (SIGKILL, power
/// outage) caused the lockfile not to be deleted.
#[derive(Debug)]
pub struct Lockfile {
    file: File,
    path: PathBuf,
}

#[derive(Debug)]
pub enum LockfileError {
    FileLocked(PathBuf, io::Error),
    UnableToCreateFile(io::Error),
}

impl Lockfile {
    /// Obtain an exclusive lock on the file at `path`, creating it if it doesn't exist.
    pub fn new(path: PathBuf) -> Result<Self, LockfileError> {
        let file = File::create(&path).map_err(LockfileError::UnableToCreateFile)?;
        file.try_lock_exclusive()
            .map_err(|e| LockfileError::FileLocked(path.clone(), e))?;
        Ok(Self { file, path })
    }
}

impl Drop for Lockfile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
