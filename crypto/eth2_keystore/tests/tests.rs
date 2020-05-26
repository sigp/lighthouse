#![cfg(test)]
#![cfg(not(debug_assertions))]

use bls::Keypair;
use eth2_keystore::{
    default_kdf,
    json_keystore::{Kdf, Pbkdf2, Prf, Scrypt},
    Error, Keystore, KeystoreBuilder, DKLEN,
};
use std::fs::OpenOptions;
use tempfile::tempdir;

const GOOD_PASSWORD: &[u8] = &[42, 42, 42];
const BAD_PASSWORD: &[u8] = &[43, 43, 43];

#[test]
fn empty_password() {
    assert_eq!(
        KeystoreBuilder::new(&Keypair::random(), "".as_bytes(), "".into())
            .err()
            .unwrap(),
        Error::EmptyPassword
    );
}

#[test]
fn string_round_trip() {
    let keypair = Keypair::random();

    let keystore = KeystoreBuilder::new(&keypair, GOOD_PASSWORD, "".into())
        .unwrap()
        .build()
        .unwrap();

    let json = keystore.to_json_string().unwrap();
    let decoded = Keystore::from_json_str(&json).unwrap();

    assert_eq!(
        decoded.decrypt_keypair(BAD_PASSWORD).err().unwrap(),
        Error::InvalidPassword,
        "should not decrypt with bad password"
    );

    assert_eq!(
        decoded.decrypt_keypair(GOOD_PASSWORD).unwrap().pk,
        keypair.pk,
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

    let keystore = KeystoreBuilder::new(&keypair, GOOD_PASSWORD, "".into())
        .unwrap()
        .build()
        .unwrap();

    keystore
        .to_json_writer(&mut get_file())
        .expect("should write to file");

    let decoded = Keystore::from_json_reader(&mut get_file()).expect("should read from file");

    assert_eq!(
        decoded.decrypt_keypair(BAD_PASSWORD).err().unwrap(),
        Error::InvalidPassword,
        "should not decrypt with bad password"
    );

    assert_eq!(
        decoded.decrypt_keypair(GOOD_PASSWORD).unwrap().pk,
        keypair.pk,
        "should decrypt with good password"
    );
}

#[test]
fn scrypt_params() {
    let keypair = Keypair::random();

    let keystore = KeystoreBuilder::new(&keypair, GOOD_PASSWORD, "".into())
        .unwrap()
        .build()
        .unwrap();

    let json = keystore.to_json_string().unwrap();
    let decoded = Keystore::from_json_str(&json).unwrap();

    assert_eq!(
        decoded.decrypt_keypair(BAD_PASSWORD).err().unwrap(),
        Error::InvalidPassword,
        "should not decrypt with bad password"
    );

    assert_eq!(
        decoded.decrypt_keypair(GOOD_PASSWORD).unwrap().pk,
        keypair.pk,
        "should decrypt with good password"
    );
}

#[test]
fn custom_scrypt_kdf() {
    let keypair = Keypair::random();

    let salt = vec![42];

    let my_kdf = Kdf::Scrypt(Scrypt {
        dklen: DKLEN,
        n: 2,
        p: 1,
        r: 8,
        salt: salt.clone().into(),
    });

    assert!(my_kdf != default_kdf(salt));

    let keystore = KeystoreBuilder::new(&keypair, GOOD_PASSWORD, "".into())
        .unwrap()
        .kdf(my_kdf.clone())
        .build()
        .unwrap();

    assert_eq!(keystore.kdf(), &my_kdf);
}

#[test]
fn custom_pbkdf2_kdf() {
    let keypair = Keypair::random();

    let salt = vec![42];

    let my_kdf = Kdf::Pbkdf2(Pbkdf2 {
        dklen: DKLEN,
        c: 2,
        prf: Prf::HmacSha256,
        salt: salt.clone().into(),
    });

    assert!(my_kdf != default_kdf(salt));

    let keystore = KeystoreBuilder::new(&keypair, GOOD_PASSWORD, "".into())
        .unwrap()
        .kdf(my_kdf.clone())
        .build()
        .unwrap();

    assert_eq!(keystore.kdf(), &my_kdf);
}
