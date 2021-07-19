use fs2::FileExt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};

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
    file_existed: bool,
}

#[derive(Debug)]
pub enum LockfileError {
    FileLocked(PathBuf, io::Error),
    IoError(PathBuf, io::Error),
    UnableToOpenFile(PathBuf, io::Error),
}

impl Lockfile {
    /// Obtain an exclusive lock on the file at `path`, creating it if it doesn't exist.
    pub fn new(path: PathBuf) -> Result<Self, LockfileError> {
        let file_existed = path.exists();
        let file = if file_existed {
            File::open(&path)
        } else {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
        }
        .map_err(|e| LockfileError::UnableToOpenFile(path.clone(), e))?;

        file.try_lock_exclusive().map_err(|e| match e.kind() {
            ErrorKind::WouldBlock => LockfileError::FileLocked(path.clone(), e),
            _ => LockfileError::IoError(path.clone(), e),
        })?;
        Ok(Self {
            file,
            path,
            file_existed,
        })
    }

    /// Return `true` if the lockfile existed when the lock was created.
    ///
    /// This could indicate another process that isn't aware of the OS lock using the file,
    /// or an ungraceful shutdown that caused the file not to be deleted.
    pub fn file_existed(&self) -> bool {
        self.file_existed
    }

    /// The path of the lockfile.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Lockfile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tempfile::tempdir;

    #[cfg(unix)]
    use std::{fs::Permissions, os::unix::fs::PermissionsExt};

    #[test]
    fn new_lock() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("lockfile");
        let _lock = Lockfile::new(path.clone()).unwrap();
        if cfg!(windows) {
            assert!(matches!(
                Lockfile::new(path).unwrap_err(),
                // windows returns an IoError because the lockfile is already open :/
                LockfileError::IoError(..),
            ));
        } else {
            assert!(matches!(
                Lockfile::new(path).unwrap_err(),
                LockfileError::FileLocked(..)
            ));
        }
    }

    #[test]
    fn relock_after_drop() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("lockfile");

        let lock1 = Lockfile::new(path.clone()).unwrap();
        drop(lock1);
        let lock2 = Lockfile::new(path.clone()).unwrap();
        assert!(!lock2.file_existed());
        drop(lock2);

        assert!(!path.exists());
    }

    #[test]
    fn lockfile_exists() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("lockfile");

        let _lockfile = File::create(&path).unwrap();

        let lock = Lockfile::new(path).unwrap();
        assert!(lock.file_existed());
    }

    #[test]
    #[cfg(unix)]
    fn permission_denied_create() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("lockfile");

        let lockfile = File::create(&path).unwrap();
        lockfile
            .set_permissions(Permissions::from_mode(0o000))
            .unwrap();

        assert!(matches!(
            Lockfile::new(path).unwrap_err(),
            LockfileError::UnableToOpenFile(..)
        ));
    }
}
