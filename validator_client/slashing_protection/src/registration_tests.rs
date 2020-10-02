#![cfg(test)]

use crate::test_utils::*;
use crate::*;
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
