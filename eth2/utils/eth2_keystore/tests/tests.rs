#![cfg(test)]

use bls::Keypair;
use eth2_keystore::{Error, Keystore, KeystoreBuilder, Password};

fn password() -> Password {
    "ilikecats".to_string().into()
}

fn bad_password() -> Password {
    "idontlikecats".to_string().into()
}

#[test]
fn empty_password() {
    assert_eq!(
        KeystoreBuilder::new(&Keypair::random(), "".into())
            .err()
            .unwrap(),
        Error::EmptyPassword
    );
}

#[test]
fn string_round_trip() {
    let keypair = Keypair::random();

    let keystore = KeystoreBuilder::new(&keypair, password())
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
        decoded.decrypt_keypair(password()).unwrap(),
        keypair,
        "should decrypt with good password"
    );
}
