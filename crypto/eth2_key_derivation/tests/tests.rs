#![cfg(test)]

use eth2_key_derivation::DerivedKey;

#[test]
fn empty_seed() {
    assert!(
        DerivedKey::from_seed(&[]).is_err(),
        "empty seed should fail"
    );
}

#[test]
fn deterministic() {
    assert_eq!(
        DerivedKey::from_seed(&[42]).unwrap().secret(),
        DerivedKey::from_seed(&[42]).unwrap().secret()
    );
}

#[test]
fn children_deterministic() {
    let master = DerivedKey::from_seed(&[42]).unwrap();
    assert_eq!(
        master.child(u32::max_value()).secret(),
        master.child(u32::max_value()).secret(),
    )
}
