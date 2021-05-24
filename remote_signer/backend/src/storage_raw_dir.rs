use crate::{BackendError, Storage, ZeroizeString, PUBLIC_KEY_REGEX};
use std::fs::read_dir;
use std::fs::File;
use std::io::prelude::Read;
use std::io::BufReader;
use std::path::Path;
use std::path::PathBuf;

#[derive(Clone)]
pub struct StorageRawDir {
    path: PathBuf,
}

impl StorageRawDir {
    /// Initializes the storage with the given path, verifying
    /// whether it is a directory and if its available to the user.
    /// Does not list, nor verify the contents of the directory.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path = path.as_ref();

        if !path.exists() {
            return Err("Path does not exist.".to_string());
        }

        if !path.is_dir() {
            return Err("Path is not a directory.".to_string());
        }

        read_dir(path).map_err(|e| format!("{:?}", e.kind()))?;

        Ok(Self {
            path: path.to_path_buf(),
        })
    }
}

impl Storage for StorageRawDir {
    /// List all the files in the directory having a BLS public key name.
    /// This function DOES NOT check the contents of each file.
    fn get_keys(&self) -> Result<Vec<String>, BackendError> {
        let entries = read_dir(&self.path).map_err(BackendError::from)?;

        // We are silently suppressing errors in this chain
        // because we only care about files actually passing these filters.
        let keys: Vec<String> = entries
            .filter_map(|entry| entry.ok())
            .filter(|entry| !entry.path().is_dir())
            .map(|entry| entry.file_name().into_string())
            .filter_map(|entry| entry.ok())
            .filter(|name| PUBLIC_KEY_REGEX.is_match(name))
            .collect();

        Ok(keys)
    }

    /// Gets a requested secret key by their reference, its public key.
    /// This function DOES NOT check the contents of the retrieved file.
    fn get_secret_key(&self, input: &str) -> Result<ZeroizeString, BackendError> {
        let file = File::open(self.path.join(input)).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => BackendError::KeyNotFound(input.to_string()),
            _ => e.into(),
        })?;
        let mut buf_reader = BufReader::new(file);

        let mut secret_key = String::new();
        buf_reader.read_to_string(&mut secret_key)?;

        // Remove that `\n` without cloning.
        secret_key.pop();

        Ok(ZeroizeString::from(secret_key))
    }
}

#[cfg(test)]
mod get_keys {
    use crate::tests_commons::*;
    use helpers::*;

    #[test]
    fn problem_with_path() {
        let (storage, tmp_dir) = new_storage_with_tmp_dir();
        add_key_files(&tmp_dir);

        // All good and fancy, let's make the dir innacessible now.
        restrict_permissions(tmp_dir.path());

        let result = storage.get_keys();

        // Give permissions back, we want the tempdir to be deleted.
        unrestrict_permissions(tmp_dir.path());

        assert_eq!(
            result.unwrap_err().to_string(),
            "Storage error: PermissionDenied"
        );
    }

    #[test]
    fn no_files_in_dir() {
        let (storage, _tmp_dir) = new_storage_with_tmp_dir();

        assert_eq!(storage.get_keys().unwrap().len(), 0);
    }

    #[test]
    fn no_files_in_dir_are_public_keys() {
        let (storage, tmp_dir) = new_storage_with_tmp_dir();
        add_sub_dirs(&tmp_dir);
        add_non_key_files(&tmp_dir);

        assert_eq!(storage.get_keys().unwrap().len(), 0);
    }

    #[test]
    fn not_all_files_have_public_key_names() {
        let (storage, tmp_dir) = new_storage_with_tmp_dir();
        add_sub_dirs(&tmp_dir);
        add_key_files(&tmp_dir);
        add_non_key_files(&tmp_dir);

        assert_eq!(storage.get_keys().unwrap().len(), 3);
    }

    #[test]
    fn all_files_do_have_public_key_names() {
        let (storage, tmp_dir) = new_storage_with_tmp_dir();
        add_key_files(&tmp_dir);

        assert_eq!(storage.get_keys().unwrap().len(), 3);
    }
}

#[cfg(test)]
mod get_secret_key {
    use crate::tests_commons::*;
    use helpers::*;

    #[test]
    fn unaccessible_file() {
        let (storage, tmp_dir) = new_storage_with_tmp_dir();
        add_key_files(&tmp_dir);

        restrict_permissions(tmp_dir.path());
        restrict_permissions(&tmp_dir.path().join(PUBLIC_KEY_1));

        let result = storage.get_secret_key(PUBLIC_KEY_1);

        unrestrict_permissions(tmp_dir.path());
        unrestrict_permissions(&tmp_dir.path().join(PUBLIC_KEY_1));

        assert_eq!(
            result.unwrap_err().to_string(),
            "Storage error: PermissionDenied"
        );
    }

    #[test]
    fn key_does_not_exist() {
        let (storage, _tmp_dir) = new_storage_with_tmp_dir();

        assert_eq!(
            storage
                .get_secret_key(PUBLIC_KEY_1)
                .unwrap_err()
                .to_string(),
            format!("Key not found: {}", PUBLIC_KEY_1)
        );
    }

    #[test]
    fn happy_path() {
        let (storage, tmp_dir) = new_storage_with_tmp_dir();
        add_key_files(&tmp_dir);

        assert_eq!(
            storage.get_secret_key(PUBLIC_KEY_1).unwrap().as_ref(),
            SECRET_KEY_1.as_bytes()
        );
    }
}
