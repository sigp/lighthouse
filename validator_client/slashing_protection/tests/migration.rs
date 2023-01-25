//! Tests for upgrading a previous version of the database to the latest schema.
use slashing_protection::{NotSafe, SlashingDatabase};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;
use types::Hash256;

fn test_data_dir() -> PathBuf {
    Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("migration-tests")
}

/// Copy `filename` from the test data dir to the temporary `dest` for testing.
fn make_copy(filename: &str, dest: &Path) -> PathBuf {
    let source_file = test_data_dir().join(filename);
    let dest_file = dest.join(filename);
    fs::copy(source_file, &dest_file).unwrap();
    dest_file
}

#[test]
fn add_enabled_column() {
    let tmp = tempdir().unwrap();

    let path = make_copy("v0_no_enabled_column.sqlite", tmp.path());
    let num_expected_validators = 5;

    // Database should open without errors, indicating successfull application of migrations.
    // The input file has no `enabled` column, which should get added when opening it here.
    let db = SlashingDatabase::open(&path).unwrap();

    // Check that exporting an interchange file lists all the validators.
    let interchange = db.export_all_interchange_info(Hash256::zero()).unwrap();
    assert_eq!(interchange.data.len(), num_expected_validators);

    db.with_transaction(|txn| {
        // Check that all the validators are enabled and unique.
        let uniq_validator_ids = interchange
            .data
            .iter()
            .map(|data| {
                let (validator_id, enabled) = db
                    .get_validator_id_with_status(txn, &data.pubkey)
                    .unwrap()
                    .unwrap();
                assert!(enabled);
                (validator_id, data.pubkey)
            })
            .collect::<HashMap<_, _>>();

        assert_eq!(uniq_validator_ids.len(), num_expected_validators);

        // Check that we can disable them all.
        for (&validator_id, pubkey) in &uniq_validator_ids {
            db.update_validator_status(txn, validator_id, false)
                .unwrap();
            let (loaded_id, enabled) = db
                .get_validator_id_with_status(txn, pubkey)
                .unwrap()
                .unwrap();
            assert_eq!(validator_id, loaded_id);
            assert!(!enabled);
        }

        Ok::<_, NotSafe>(())
    })
    .unwrap();
}
