#![cfg(test)]
#![cfg(not(debug_assertions))]

use bls::Keypair;
use eth2_keystore::{
    DKLEN, Error, Keystore, KeystoreBuilder, default_kdf,
    json_keystore::{Kdf, Pbkdf2, Prf, Scrypt},
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

    let keystore = KeystoreBuilder::new(&keypair, GOOD_PASSWORD, "".into())
        .unwrap()
        .build()
        .unwrap();

    keystore
        .to_json_writer(File::create_new(&path).unwrap())
        .expect("should write to file");

    let decoded =
        Keystore::from_json_reader(File::open(&path).unwrap()).expect("should read from file");

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

/// Test that verifies AES-128-CTR uses big-endian counter increment.
///
/// This test uses the official EIP-2335 test vectors to verify that the AES-128-CTR
/// implementation correctly uses big-endian byte order for counter incrementation.
/// The test vectors were specifically designed to validate compliance with RFC 3686
/// and NIST SP 800-38A, which both mandate big-endian counter behavior.
///
/// If the endianness were incorrect (e.g., using little-endian), this test would
/// fail because the decrypted secret would not match the expected value.
#[test]
fn aes_ctr_endianness_verification() {
    // This test vector is from EIP-2335 specification
    // Password: "testpassword" (from the simplified test in the spec)
    let password = b"testpassword";

    // Expected secret key after decryption
    let expected_secret =
        hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
            .expect("valid hex");

    // EIP-2335 test vector with scrypt KDF
    let keystore_json = r#"
        {
        "crypto": {
            "kdf": {
                "function": "scrypt",
                "params": {
                    "dklen": 32,
                    "n": 262144,
                    "p": 1,
                    "r": 8,
                    "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                },
                "message": ""
            },
            "checksum": {
                "function": "sha256",
                "params": {},
                "message": "149aafa27b041f3523c53d7acba1905fa6b1c90f9fef137568101f44b531a3cb"
            },
            "cipher": {
                "function": "aes-128-ctr",
                "params": {
                    "iv": "264daa3f303d7259501c93d997d84fe6"
                },
                "message": "54ecc8863c0550351eee5720f3be6a5d4a016025aa91cd6436cfec938d6a8d30"
            }
        },
        "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
        "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
        "path": "",
        "version": 4
    }
    "#;

    let keystore = Keystore::from_json_str(keystore_json).expect("should parse keystore JSON");

    let keypair = keystore
        .decrypt_keypair(password)
        .expect("should decrypt with correct password");

    // Verify the decrypted secret matches the expected value
    // This proves the AES-CTR counter is being incremented in big-endian format
    assert_eq!(
        keypair.sk.serialize().as_ref(),
        &expected_secret[..],
        "Decrypted secret key should match expected value. \
         If this fails, the AES-CTR counter increment endianness may be incorrect."
    );

    // Also verify the public key matches
    assert_eq!(
        format!("0x{}", keystore.pubkey()),
        format!("{:?}", keystore.public_key().unwrap()),
        "Public key should match"
    );
}
