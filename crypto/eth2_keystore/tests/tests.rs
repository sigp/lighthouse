#![cfg(test)]
#![cfg(not(debug_assertions))]

use bls::Keypair;
use eth2_keystore::{
    default_kdf,
    json_keystore::{Kdf, Pbkdf2, Prf, Scrypt},
    Error, Keystore, KeystoreBuilder, DKLEN,
};
use std::fs::File;
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
        File::options()
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
    let salt = vec![42; 32];

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

    // n <= 1
    let my_kdf = Kdf::Scrypt(Scrypt {
        dklen: DKLEN,
        n: 1,
        p: 1,
        r: 8,
        salt: salt.clone().into(),
    });
    let keystore = KeystoreBuilder::new(&keypair, GOOD_PASSWORD, "".into())
        .unwrap()
        .kdf(my_kdf.clone())
        .build();
    assert_eq!(keystore, Err(Error::InvalidScryptParam));

    // p != 0
    let my_kdf = Kdf::Scrypt(Scrypt {
        dklen: DKLEN,
        n: 16,
        p: 0,
        r: 8,
        salt: salt.clone().into(),
    });
    let keystore = KeystoreBuilder::new(&keypair, GOOD_PASSWORD, "".into())
        .unwrap()
        .kdf(my_kdf.clone())
        .build();
    assert_eq!(keystore, Err(Error::InvalidScryptParam));

    // r != 0
    let my_kdf = Kdf::Scrypt(Scrypt {
        dklen: DKLEN,
        n: 16,
        p: 1,
        r: 0,
        salt: salt.clone().into(),
    });
    let keystore = KeystoreBuilder::new(&keypair, GOOD_PASSWORD, "".into())
        .unwrap()
        .kdf(my_kdf.clone())
        .build();
    assert_eq!(keystore, Err(Error::InvalidScryptParam));

    // 128 * n * p * r overflow
    let my_kdf = Kdf::Scrypt(Scrypt {
        dklen: DKLEN,
        n: 1 << 31,
        p: 1 << 31,
        r: 1 << 31,
        salt: salt.clone().into(),
    });
    let keystore = KeystoreBuilder::new(&keypair, GOOD_PASSWORD, "".into())
        .unwrap()
        .kdf(my_kdf.clone())
        .build();
    assert_eq!(keystore, Err(Error::InvalidScryptParam));
}

#[test]
fn pbkdf2_params() {
    let keypair = Keypair::random();

    let salt = vec![42; 32];

    let my_kdf = Kdf::Pbkdf2(Pbkdf2 {
        dklen: DKLEN,
        c: 80_000_001,
        prf: Prf::HmacSha256,
        salt: salt.clone().into(),
    });
    let keystore = KeystoreBuilder::new(&keypair, GOOD_PASSWORD, "".into())
        .unwrap()
        .kdf(my_kdf.clone())
        .build();
    assert_eq!(keystore, Err(Error::InvalidPbkdf2Param));

    let my_kdf = Kdf::Pbkdf2(Pbkdf2 {
        dklen: DKLEN + 1,
        c: 4,
        prf: Prf::HmacSha256,
        salt: salt.clone().into(),
    });
    let keystore = KeystoreBuilder::new(&keypair, GOOD_PASSWORD, "".into())
        .unwrap()
        .kdf(my_kdf.clone())
        .build();
    assert_eq!(keystore, Err(Error::InvalidPbkdf2Param));
}

#[test]
fn custom_scrypt_kdf() {
    let keypair = Keypair::random();

    let salt = vec![42; 32];

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

    let salt = vec![42; 32];

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

#[test]
fn utf8_control_characters() {
    let keypair = Keypair::random();

    let password = vec![42, 42, 42];
    let password_with_control_chars = vec![0x7Fu8, 42, 42, 42];

    let keystore1 = KeystoreBuilder::new(&keypair, &password_with_control_chars, "".into())
        .unwrap()
        .build()
        .unwrap();

    let keystore2 = KeystoreBuilder::new(&keypair, &password, "".into())
        .unwrap()
        .build()
        .unwrap();

    assert_eq!(keystore1.pubkey(), keystore2.pubkey());

    // Decode same keystore with nfc and nfkd form passwords
    let decoded1 = keystore1
        .decrypt_keypair(&password_with_control_chars)
        .unwrap();
    let decoded2 = keystore1.decrypt_keypair(&password).unwrap();

    assert_eq!(decoded1.pk, keypair.pk);
    assert_eq!(decoded2.pk, keypair.pk);
}

#[test]
fn normalization() {
    use unicode_normalization::UnicodeNormalization;

    let keypair = Keypair::random();
    let password_str = "Zoë";

    let password_nfc: String = password_str.nfc().collect();
    let password_nfkd: String = password_str.nfkd().collect();

    assert_ne!(password_nfc, password_nfkd);

    let keystore_nfc = KeystoreBuilder::new(&keypair, password_nfc.as_bytes(), "".into())
        .unwrap()
        .build()
        .unwrap();

    let keystore_nfkd = KeystoreBuilder::new(&keypair, password_nfkd.as_bytes(), "".into())
        .unwrap()
        .build()
        .unwrap();

    assert_eq!(keystore_nfc.pubkey(), keystore_nfkd.pubkey());

    // Decode same keystore with nfc and nfkd form passwords
    let decoded_nfc = keystore_nfc
        .decrypt_keypair(password_nfc.as_bytes())
        .unwrap();
    let decoded_nfkd = keystore_nfc
        .decrypt_keypair(password_nfkd.as_bytes())
        .unwrap();

    assert_eq!(decoded_nfc.pk, keypair.pk);
    assert_eq!(decoded_nfkd.pk, keypair.pk);
}
