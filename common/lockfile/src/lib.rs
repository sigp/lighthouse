use fs2::FileExt;
use std::fs::{self, File};
use std::io;
use std::path::PathBuf;

/// Cross-platform file lock that auto-deletes on drop, but doesn't fail if the file already exists.
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
        let file = File::create(&path).map_err(|e| LockfileError::UnableToCreateFile(e))?;
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
