mod error;
mod storage;
mod storage_raw_dir;
mod utils;
mod zeroize_string;

use crate::zeroize_string::ZeroizeString;
use bls::SecretKey;
use clap::ArgMatches;
pub use error::BackendError;
use lazy_static::lazy_static;
use regex::Regex;
use slog::{info, Logger};
pub use storage::Storage;
use storage_raw_dir::StorageRawDir;
use types::Hash256;
use utils::{bytes96_to_hex_string, validate_bls_pair};

lazy_static! {
    static ref PUBLIC_KEY_REGEX: Regex = Regex::new(r"[0-9a-fA-F]{96}").unwrap();
}

/// A backend to be used by the Remote Signer HTTP API.
///
/// Designed to support several types of storages.
#[derive(Clone)]
pub struct Backend<T> {
    storage: T,
}

impl Backend<StorageRawDir> {
    /// Creates a Backend with the given storage type at the CLI arguments.
    ///
    /// # Storage types supported
    ///
    /// * Raw files in directory: `--storage-raw-dir <DIR>`
    ///
    pub fn new(cli_args: &ArgMatches<'_>, log: &Logger) -> Result<Self, String> {
        // Storage types are mutually exclusive.
        if let Some(path) = cli_args.value_of("storage-raw-dir") {
            info!(
                log,
                "Loading Backend";
                "storage type" => "raw dir",
                "directory" => path
            );

            StorageRawDir::new(path)
                .map(|storage| Self { storage })
                .map_err(|e| format!("Storage Raw Dir: {}", e))
        } else {
            Err("No storage type supplied.".to_string())
        }
    }
}

impl<T: Storage> Backend<T> {
    /// Returns the available public keys in storage.
    pub fn get_keys(&self) -> Result<Vec<String>, BackendError> {
        self.storage.get_keys()
    }

    /// Signs the message with the requested key in storage.
    pub fn sign_message(
        &self,
        public_key: &str,
        signing_root: Hash256,
    ) -> Result<String, BackendError> {
        if !PUBLIC_KEY_REGEX.is_match(public_key) || public_key.len() != 96 {
            return Err(BackendError::InvalidPublicKey(public_key.to_string()));
        }

        let secret_key: ZeroizeString = self.storage.get_secret_key(public_key)?;
        let secret_key: SecretKey = validate_bls_pair(public_key, secret_key)?;

        let signature = secret_key.sign(signing_root);

        let signature: String = bytes96_to_hex_string(signature.serialize())
            .expect("Writing to a string should never error.");

        Ok(signature)
    }
}

#[cfg(test)]
pub mod tests_commons {
    use super::*;
    pub use crate::Storage;
    use helpers::*;
    use sloggers::{null::NullLoggerBuilder, Build};
    use tempfile::{tempdir, TempDir};

    type T = StorageRawDir;

    pub fn new_storage_with_tmp_dir() -> (T, TempDir) {
        let tmp_dir = tempdir().unwrap();
        let storage = StorageRawDir::new(tmp_dir.path().to_str().unwrap()).unwrap();
        (storage, tmp_dir)
    }

    pub fn get_null_logger() -> Logger {
        let log_builder = NullLoggerBuilder;
        log_builder.build().unwrap()
    }

    pub fn new_backend_for_get_keys() -> (Backend<T>, TempDir) {
        let tmp_dir = tempdir().unwrap();

        let matches = set_matches(vec![
            "this_test",
            "--storage-raw-dir",
            tmp_dir.path().to_str().unwrap(),
        ]);

        let backend = match Backend::new(&matches, &get_null_logger()) {
            Ok(backend) => (backend),
            Err(e) => panic!("We should not be getting an err here: {}", e),
        };

        (backend, tmp_dir)
    }

    pub fn new_backend_for_signing() -> (Backend<T>, TempDir) {
        let (backend, tmp_dir) = new_backend_for_get_keys();

        // This one has the whole fauna.
        add_sub_dirs(&tmp_dir);
        add_key_files(&tmp_dir);
        add_non_key_files(&tmp_dir);
        add_mismatched_key_file(&tmp_dir);

        (backend, tmp_dir)
    }

    pub fn assert_backend_new_error(matches: &ArgMatches, error_msg: &str) {
        match Backend::new(matches, &get_null_logger()) {
            Ok(_) => panic!("This invocation to Backend::new() should return error"),
            Err(e) => assert_eq!(e, error_msg),
        }
    }
}

#[cfg(test)]
pub mod backend_new {
    use super::*;
    use crate::tests_commons::*;
    use helpers::*;
    use tempfile::tempdir;

    #[test]
    fn no_storage_type_supplied() {
        let matches = set_matches(vec!["this_test"]);

        assert_backend_new_error(&matches, "No storage type supplied.");
    }

    #[test]
    fn given_path_does_not_exist() {
        let matches = set_matches(vec!["this_test", "--storage-raw-dir", "/dev/null/foo"]);

        assert_backend_new_error(&matches, "Storage Raw Dir: Path does not exist.");
    }

    #[test]
    fn given_path_is_not_a_dir() {
        let matches = set_matches(vec![
            "this_test",
            "--storage-raw-dir",
            match cfg!(windows) {
                true => "C:\\Windows\\system.ini",
                false => "/dev/null",
            },
        ]);

        assert_backend_new_error(&matches, "Storage Raw Dir: Path is not a directory.");
    }

    #[test]
    fn given_inaccessible() {
        let tmp_dir = tempdir().unwrap();
        restrict_permissions(tmp_dir.path());

        let matches = set_matches(vec![
            "this_test",
            "--storage-raw-dir",
            tmp_dir.path().to_str().unwrap(),
        ]);

        let result = Backend::new(&matches, &get_null_logger());

        // A `d-wx--x--x` directory is innaccesible but not unwrittable.
        // By switching back to `drwxr-xr-x` we can get rid of the
        // temporal directory once we leave this scope.
        unrestrict_permissions(tmp_dir.path());

        match result {
            Ok(_) => panic!("This invocation to Backend::new() should return error"),
            Err(e) => assert_eq!(e, "Storage Raw Dir: PermissionDenied",),
        }
    }

    #[test]
    fn happy_path() {
        let (_backend, _tmp_dir) = new_backend_for_get_keys();
    }
}

#[cfg(test)]
pub mod backend_raw_dir_get_keys {
    use crate::tests_commons::*;
    use helpers::*;

    #[test]
    fn empty_dir() {
        let (backend, _tmp_dir) = new_backend_for_get_keys();

        assert_eq!(backend.get_keys().unwrap().len(), 0);
    }

    #[test]
    fn some_files_are_not_public_keys() {
        let (backend, tmp_dir) = new_backend_for_get_keys();

        add_sub_dirs(&tmp_dir);
        add_key_files(&tmp_dir);
        add_non_key_files(&tmp_dir);

        assert_eq!(backend.get_keys().unwrap().len(), 3);
    }

    #[test]
    fn all_files_are_public_keys() {
        let (backend, tmp_dir) = new_backend_for_get_keys();
        add_key_files(&tmp_dir);

        assert_eq!(backend.get_keys().unwrap().len(), 3);
    }
}

#[cfg(test)]
pub mod backend_raw_dir_sign_message {
    use crate::tests_commons::*;
    use helpers::*;
    use types::Hash256;

    #[test]
    fn invalid_public_key() {
        let (backend, _tmp_dir) = new_backend_for_signing();

        let test_case = |public_key_param: &str| {
            assert_eq!(
                backend
                    .clone()
                    .sign_message(
                        public_key_param,
                        Hash256::from_slice(&hex::decode(SIGNING_ROOT).unwrap())
                    )
                    .unwrap_err()
                    .to_string(),
                format!("Invalid public key: {}", public_key_param)
            );
        };

        test_case("abcdef"); // Length < 96.
        test_case(&format!("{}55", PUBLIC_KEY_1)); // Length > 96.
        test_case(SILLY_FILE_NAME_1); // Length == 96; Invalid hex characters.
    }

    #[test]
    fn storage_error() {
        let (backend, tmp_dir) = new_backend_for_signing();

        restrict_permissions(tmp_dir.path());
        restrict_permissions(&tmp_dir.path().join(PUBLIC_KEY_1));

        let result = backend.sign_message(
            PUBLIC_KEY_1,
            Hash256::from_slice(&hex::decode(SIGNING_ROOT).unwrap()),
        );

        unrestrict_permissions(tmp_dir.path());
        unrestrict_permissions(&tmp_dir.path().join(PUBLIC_KEY_1));

        assert_eq!(
            result.unwrap_err().to_string(),
            "Storage error: PermissionDenied"
        );
    }

    #[test]
    fn key_not_found() {
        let (backend, _tmp_dir) = new_backend_for_signing();

        assert_eq!(
            backend
                .sign_message(
                    ABSENT_PUBLIC_KEY,
                    Hash256::from_slice(&hex::decode(SIGNING_ROOT).unwrap())
                )
                .unwrap_err()
                .to_string(),
            format!("Key not found: {}", ABSENT_PUBLIC_KEY)
        );
    }

    #[test]
    fn key_mismatch() {
        let (backend, _tmp_dir) = new_backend_for_signing();

        assert_eq!(
            backend
                .sign_message(
                    MISMATCHED_PUBLIC_KEY,
                    Hash256::from_slice(&hex::decode(SIGNING_ROOT).unwrap())
                )
                .unwrap_err()
                .to_string(),
            format!("Key mismatch: {}", MISMATCHED_PUBLIC_KEY)
        );
    }

    #[test]
    fn happy_path() {
        let (backend, _tmp_dir) = new_backend_for_signing();

        let test_case = |public_key: &str, signature: &str| {
            assert_eq!(
                backend
                    .clone()
                    .sign_message(
                        public_key,
                        Hash256::from_slice(&hex::decode(SIGNING_ROOT).unwrap())
                    )
                    .unwrap(),
                signature
            );
        };

        test_case(PUBLIC_KEY_1, EXPECTED_SIGNATURE_1);
        test_case(PUBLIC_KEY_2, EXPECTED_SIGNATURE_2);
        test_case(PUBLIC_KEY_3, EXPECTED_SIGNATURE_3);
    }
}
