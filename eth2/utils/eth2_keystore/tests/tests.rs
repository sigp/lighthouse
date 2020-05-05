#![cfg(test)]

use bls::Keypair;
use eth2_keystore::{Error, Keystore, KeystoreBuilder, Password};
use std::fs::OpenOptions;
use tempfile::tempdir;

fn good_password() -> Password {
    "ilikecats".to_string().into()
}

fn bad_password() -> Password {
    "idontlikecats".to_string().into()
}

#[test]
fn empty_password() {
    assert_eq!(
        KeystoreBuilder::new(&Keypair::random(), "".into(), "".into())
            .err()
            .unwrap(),
        Error::EmptyPassword
    );
}

#[test]
fn string_round_trip() {
    let keypair = Keypair::random();

    let keystore = KeystoreBuilder::new(&keypair, good_password(), "".into())
        .unwrap()
        .build()
        .unwrap();

    let json = keystore.to_json_string().unwrap();
    let decoded = Keystore::from_json_str(&json).unwrap();

    assert_eq!(
        decoded.decrypt_keypair(bad_password()).err().unwrap(),
        Error::InvalidPassword,
        "should not decrypt with bad password"
    );

    assert_eq!(
        decoded.decrypt_keypair(good_password()).unwrap(),
        keypair,
        "should decrypt with good password"
    );
}

#[test]
fn file() {
    let keypair = Keypair::random();
    let dir = tempdir().unwrap();
    let path = dir.path().join("keystore.json");

    let get_file = || {
        OpenOptions::new()
            .write(true)
            .read(true)
            .create(true)
            .open(path.clone())
            .expect("should create file")
    };

    let keystore = KeystoreBuilder::new(&keypair, good_password(), "".into())
        .unwrap()
        .build()
        .unwrap();

    keystore
        .to_json_writer(&mut get_file())
        .expect("should write to file");

    let decoded = Keystore::from_json_reader(&mut get_file()).expect("should read from file");

    assert_eq!(
        decoded.decrypt_keypair(bad_password()).err().unwrap(),
        Error::InvalidPassword,
        "should not decrypt with bad password"
    );

    assert_eq!(
        decoded.decrypt_keypair(good_password()).unwrap(),
        keypair,
        "should decrypt with good password"
    );
}
