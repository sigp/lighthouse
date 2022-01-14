#![cfg(test)]

use crate::test_utils::pubkey;
use crate::*;
use tempfile::tempdir;

#[test]
fn export_non_existent_key() {
    let dir = tempdir().unwrap();
    let slashing_db_file = dir.path().join("slashing_protection.sqlite");
    let slashing_db = SlashingDatabase::create(&slashing_db_file).unwrap();

    let key1 = pubkey(1);
    let key2 = pubkey(2);

    // Exporting two non-existent keys should fail on the first one.
    let err = slashing_db
        .export_interchange_info(Hash256::zero(), Some(&[key1, key2]))
        .unwrap_err();
    assert!(matches!(
        err,
        InterchangeError::NotSafe(NotSafe::UnregisteredValidator(k)) if k == key1
    ));

    slashing_db.register_validator(key1).unwrap();

    // Exporting one key that exists and one that doesn't should fail on the one that doesn't.
    let err = slashing_db
        .export_interchange_info(Hash256::zero(), Some(&[key1, key2]))
        .unwrap_err();
    assert!(matches!(
        err,
        InterchangeError::NotSafe(NotSafe::UnregisteredValidator(k)) if k == key2
    ));

    // Exporting only keys that exist should work.
    let interchange = slashing_db
        .export_interchange_info(Hash256::zero(), Some(&[key1]))
        .unwrap();
    assert_eq!(interchange.data.len(), 1);
    assert_eq!(interchange.data[0].pubkey, key1);
}

#[test]
fn export_same_key_twice() {
    let dir = tempdir().unwrap();
    let slashing_db_file = dir.path().join("slashing_protection.sqlite");
    let slashing_db = SlashingDatabase::create(&slashing_db_file).unwrap();

    let key1 = pubkey(1);

    slashing_db.register_validator(key1).unwrap();

    let export_single = slashing_db
        .export_interchange_info(Hash256::zero(), Some(&[key1]))
        .unwrap();
    let export_double = slashing_db
        .export_interchange_info(Hash256::zero(), Some(&[key1, key1]))
        .unwrap();

    assert_eq!(export_single.data.len(), 1);

    // Allow the same data to be exported twice, this is harmless, albeit slightly inefficient.
    assert_eq!(export_double.data.len(), 2);
    assert_eq!(export_double.data[0], export_double.data[1]);

    // The data should be identical to the single export.
    assert_eq!(export_double.data[0], export_single.data[0]);

    // The minified versions should be equal too.
    assert_eq!(
        export_single.minify().unwrap(),
        export_double.minify().unwrap()
    );
}
