#![cfg(test)]

use crate::test_utils::*;
use crate::*;
use std::iter;
use tempfile::tempdir;

#[test]
fn double_register_validators() {
    let dir = tempdir().unwrap();
    let slashing_db_file = dir.path().join("slashing_protection.sqlite");
    let slashing_db = SlashingDatabase::create(&slashing_db_file).unwrap();

    let num_validators = 100u32;
    let pubkeys = (0..num_validators as usize).map(pubkey).collect::<Vec<_>>();

    let get_validator_ids = || {
        pubkeys
            .iter()
            .map(|pk| slashing_db.get_validator_id(pk).unwrap())
            .collect::<Vec<_>>()
    };

    assert_eq!(slashing_db.num_validator_rows().unwrap(), 0);

    slashing_db.register_validators(pubkeys.iter()).unwrap();
    assert_eq!(slashing_db.num_validator_rows().unwrap(), num_validators);
    let validator_ids = get_validator_ids();

    slashing_db.register_validators(pubkeys.iter()).unwrap();
    assert_eq!(slashing_db.num_validator_rows().unwrap(), num_validators);
    assert_eq!(validator_ids, get_validator_ids());
}

#[test]
fn reregister_validator() {
    let dir = tempdir().unwrap();
    let slashing_db_file = dir.path().join("slashing_protection.sqlite");
    let slashing_db = SlashingDatabase::create(&slashing_db_file).unwrap();

    let pk = pubkey(0);

    // Register validator.
    slashing_db.register_validator(pk).unwrap();
    let id = slashing_db.get_validator_id(&pk).unwrap();

    slashing_db
        .with_transaction(|txn| {
            // Disable.
            slashing_db.update_validator_status(txn, id, false)?;

            // Fetching the validator as "registered" should now fail.
            assert_eq!(
                slashing_db.get_validator_id_in_txn(txn, &pk).unwrap_err(),
                NotSafe::DisabledValidator(pk)
            );

            // Fetching its status should return false.
            let (fetched_id, enabled) =
                slashing_db.get_validator_id_with_status(txn, &pk)?.unwrap();
            assert_eq!(fetched_id, id);
            assert!(!enabled);

            // Re-registering the validator should preserve its ID while changing its status to
            // enabled.
            slashing_db.register_validators_in_txn(iter::once(&pk), txn)?;

            let re_reg_id = slashing_db.get_validator_id_in_txn(txn, &pk)?;
            assert_eq!(re_reg_id, id);

            Ok::<_, NotSafe>(())
        })
        .unwrap();
}
