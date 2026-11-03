use slasher::{Config, config::MDBX_DATA_FILENAME};
use std::fs::File;
use tempfile::tempdir;

#[test]
fn no_legacy_mdbx_db() {
    let tempdir = tempdir().unwrap();
    let config = Config::new(tempdir.path().into());
    assert_eq!(config.legacy_mdbx_database(), None);
}

#[test]
fn legacy_mdbx_db_found() {
    let tempdir = tempdir().unwrap();
    let config = Config::new(tempdir.path().into());

    let filename = config.database_path.join(MDBX_DATA_FILENAME);
    File::create(&filename).unwrap();

    assert_eq!(config.legacy_mdbx_database(), Some(filename));
}

#[test]
#[cfg(any(feature = "lmdb", feature = "redb"))]
fn open_with_legacy_mdbx_db() {
    use slasher::{
        Slasher,
        test_utils::{E, chain_spec},
    };

    let tempdir = tempdir().unwrap();
    let config = Config::new(tempdir.path().into());

    File::create(config.database_path.join(MDBX_DATA_FILENAME)).unwrap();
    File::create(config.database_path.join("mdbx.lck")).unwrap();

    Slasher::<E>::open(config, chain_spec()).unwrap();
}
