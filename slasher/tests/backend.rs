#![cfg(all(feature = "lmdb"))]

use slasher::{config::MDBX_DATA_FILENAME, Config, DatabaseBackend, DatabaseBackendOverride};
use std::fs::File;
use tempfile::tempdir;

#[test]
#[cfg(all(feature = "mdbx", feature = "lmdb"))]
fn override_no_existing_db() {
    let tempdir = tempdir().unwrap();
    let mut config = Config::new(tempdir.path().into());
    assert_eq!(config.override_backend(), DatabaseBackendOverride::Noop);
}

#[test]
#[cfg(all(feature = "mdbx", feature = "lmdb"))]
fn override_with_existing_mdbx_db() {
    let tempdir = tempdir().unwrap();
    let mut config = Config::new(tempdir.path().into());

    File::create(config.database_path.join(MDBX_DATA_FILENAME)).unwrap();

    assert_eq!(
        config.override_backend(),
        DatabaseBackendOverride::Success(DatabaseBackend::Lmdb)
    );
    assert_eq!(config.backend, DatabaseBackend::Mdbx);
}

#[test]
#[cfg(all(feature = "mdbx", feature = "lmdb"))]
fn no_override_with_existing_mdbx_db() {
    let tempdir = tempdir().unwrap();
    let mut config = Config::new(tempdir.path().into());
    config.backend = DatabaseBackend::Mdbx;

    File::create(config.database_path.join(MDBX_DATA_FILENAME)).unwrap();

    assert_eq!(config.override_backend(), DatabaseBackendOverride::Noop);
    assert_eq!(config.backend, DatabaseBackend::Mdbx);
}

#[test]
#[cfg(all(not(feature = "mdbx"), feature = "lmdb"))]
fn failed_override_with_existing_mdbx_db() {
    let tempdir = tempdir().unwrap();
    let mut config = Config::new(tempdir.path().into());

    let filename = config.database_path.join(MDBX_DATA_FILENAME);
    File::create(&filename).unwrap();

    assert_eq!(
        config.override_backend(),
        DatabaseBackendOverride::Failure(filename)
    );
    assert_eq!(config.backend, DatabaseBackend::Lmdb);
}
