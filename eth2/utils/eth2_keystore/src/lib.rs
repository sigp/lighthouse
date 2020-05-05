mod derived_key;
mod json_keystore;
mod password;
mod plain_text;

use bls::{Keypair, PublicKey, SecretKey};
use crypto::{digest::Digest, sha2::Sha256};
use derived_key::DerivedKey;
use hex::FromHexError;
use json_keystore::{
    Aes128Ctr, ChecksumModule, Cipher, CipherModule, Crypto, EmptyMap, HexBytes, JsonKeystore, Kdf,
    KdfModule, Pbkdf2, Prf, Sha256Checksum, Version,
};
use password::Password;
use plain_text::PlainText;
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use ssz::DecodeError;
use uuid::Uuid;

/// The byte-length of a BLS secret key.
const SECRET_KEY_LEN: usize = 32;
/// The default byte length of the salt used to seed the KDF.
const SALT_SIZE: usize = 32;
/// The length of the derived key.
const DKLEN: u32 = 32;
// TODO: comment
const IV_SIZE: usize = 16;
// TODO: comment
const HASH_SIZE: usize = 32;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidSecretKeyLen { len: usize, expected: usize },
    InvalidCipherMessageHex(FromHexError),
    InvalidPassword,
    InvalidSecretKeyBytes(DecodeError),
    PublicKeyMismatch,
    EmptyPassword,
    UnableToSerialize,
    InvalidJson(String),
    IncorrectIvSize { expected: usize, len: usize },
}

/// Constructs a `Keystore`.
pub struct KeystoreBuilder<'a> {
    keypair: &'a Keypair,
    password: Password,
    kdf: Kdf,
    cipher: Cipher,
    uuid: Uuid,
}

impl<'a> KeystoreBuilder<'a> {
    /// Creates a new builder.
    ///
    /// ## Errors
    ///
    /// Returns `Error::EmptyPassword` if `password == ""`.
    pub fn new(keypair: &'a Keypair, password: Password) -> Result<Self, Error> {
        if password.as_str() == "" {
            Err(Error::EmptyPassword)
        } else {
            let salt = rand::thread_rng().gen::<[u8; SALT_SIZE]>();
            let iv = rand::thread_rng().gen::<[u8; IV_SIZE]>().to_vec().into();

            Ok(Self {
                keypair,
                password,
                kdf: Kdf::Pbkdf2(Pbkdf2 {
                    dklen: DKLEN,
                    c: 262144,
                    prf: Prf::default(),
                    salt: salt.to_vec().into(),
                }),
                cipher: Cipher::Aes128Ctr(Aes128Ctr { iv }),
                uuid: Uuid::new_v4(),
            })
        }
    }

    /// Consumes `self`, returning a `Keystore`.
    pub fn build(self) -> Result<Keystore, Error> {
        Keystore::encrypt(
            self.keypair,
            self.password,
            self.kdf,
            self.cipher,
            self.uuid,
        )
    }
}

/// Provides a BLS keystore as defined in [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335).
///
/// Use `KeystoreBuilder` to create a new keystore.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Keystore {
    json: JsonKeystore,
}

impl Keystore {
    /// Generate `Keystore` object for a BLS12-381 secret key from a
    /// keypair and password.
    fn encrypt(
        keypair: &Keypair,
        password: Password,
        kdf: Kdf,
        cipher: Cipher,
        uuid: Uuid,
    ) -> Result<Self, Error> {
        // Generate derived key
        let derived_key = derive_key(&password, &kdf);

        // TODO: the keypair secret isn't zeroized.
        let secret = keypair.sk.as_raw().as_bytes();

        // Encrypt secret
        let cipher_message: Vec<u8> = match &cipher {
            Cipher::Aes128Ctr(params) => {
                // TODO: sanity checks
                // TODO: check IV size
                // cipher.encrypt(derived_key.aes_key(), &keypair.sk.as_raw().as_bytes())
                let mut cipher_text = vec![0; secret.len()];

                crypto::aes::ctr(
                    crypto::aes::KeySize::KeySize128,
                    derived_key.aes_key(),
                    &get_iv(params.iv.as_bytes())?,
                )
                .process(&secret, &mut cipher_text);
                cipher_text
            }
        };

        let crypto = Crypto {
            kdf: KdfModule {
                function: kdf.function(),
                params: kdf.clone(),
                message: HexBytes::empty(),
            },
            checksum: ChecksumModule {
                function: Sha256Checksum::function(),
                params: EmptyMap,
                message: generate_checksum(&derived_key, &cipher_message),
            },
            cipher: CipherModule {
                function: cipher.function(),
                params: cipher.clone(),
                message: cipher_message.into(),
            },
        };

        Ok(Keystore {
            json: JsonKeystore {
                crypto,
                uuid,
                // TODO: Implement `path` according to
                // https://github.com/CarlBeek/EIPs/blob/bls_path/EIPS/eip-2334.md
                // For now, `path` is set to en empty string.
                path: String::new(),
                pubkey: keypair.pk.as_hex_string()[2..].to_string(),
                version: Version::four(),
            },
        })
    }

    /// Regenerate a BLS12-381 `Keypair` from `self` and the correct password.
    ///
    /// ## Errors
    ///
    /// - The provided password is incorrect.
    /// - The keystore is badly formed.
    pub fn decrypt_keypair(&self, password: Password) -> Result<Keypair, Error> {
        let cipher_message = &self.json.crypto.cipher.message;

        // Generate derived key
        let derived_key = derive_key(&password, &self.json.crypto.kdf.params);

        // Mismatching checksum indicates an invalid password.
        if generate_checksum(&derived_key, cipher_message.as_bytes())
            != self.json.crypto.checksum.message
        {
            return Err(Error::InvalidPassword);
        }

        let sk_bytes = match &self.json.crypto.cipher.params {
            Cipher::Aes128Ctr(params) => {
                // cipher.decrypt(&derived_key.aes_key(), &cipher_message)
                let mut pt = PlainText::zero(cipher_message.len());
                crypto::aes::ctr(
                    crypto::aes::KeySize::KeySize128,
                    derived_key.aes_key(),
                    &get_iv(&params.iv.as_bytes())?,
                )
                .process(cipher_message.as_bytes(), pt.as_mut_bytes());
                pt
            }
        };

        // Verify that secret key material is correct length.
        if sk_bytes.len() != SECRET_KEY_LEN {
            return Err(Error::InvalidSecretKeyLen {
                len: sk_bytes.len(),
                expected: SECRET_KEY_LEN,
            });
        }

        // Instantiate a `SecretKey`.
        let sk =
            SecretKey::from_bytes(sk_bytes.as_bytes()).map_err(Error::InvalidSecretKeyBytes)?;

        // Derive a `PublicKey` from `SecretKey`.
        let pk = PublicKey::from_secret_key(&sk);

        // Verify that the derived `PublicKey` matches `self`.
        if pk.as_hex_string()[2..].to_string() != self.json.pubkey {
            return Err(Error::PublicKeyMismatch);
        }

        Ok(Keypair { sk, pk })
    }

    /// Returns the UUID for the keystore.
    pub fn uuid(&self) -> &Uuid {
        &self.json.uuid
    }

    /// Returns `self` encoded as a JSON object.
    pub fn to_json_string(&self) -> Result<String, Error> {
        serde_json::to_string(self).map_err(|_| Error::UnableToSerialize)
    }

    /// Returns `self` encoded as a JSON object.
    pub fn from_json_str(json_string: &str) -> Result<Self, Error> {
        serde_json::from_str(json_string).map_err(|e| Error::InvalidJson(format!("{}", e)))
    }
}

fn generate_checksum(derived_key: &DerivedKey, cipher_message: &[u8]) -> HexBytes {
    let mut hasher = Sha256::new();
    hasher.input(derived_key.checksum_slice());
    hasher.input(cipher_message);

    let mut digest = vec![0; HASH_SIZE];
    hasher.result(&mut digest);

    digest.into()
}

fn derive_key(password: &Password, kdf: &Kdf) -> DerivedKey {
    // Generate derived key
    match &kdf {
        Kdf::Pbkdf2(params) => {
            let mut dk = DerivedKey::zero();
            let mut mac = params.prf.mac(password.as_bytes());
            crypto::pbkdf2::pbkdf2(
                &mut mac,
                params.salt.as_bytes(),
                params.c,
                dk.as_mut_bytes(),
            );
            dk
        }
        Kdf::Scrypt(params) => {
            let mut dk = DerivedKey::zero();

            // Assert that `n` is power of 2
            debug_assert_eq!(params.n, 2u32.pow(log2_int(params.n)));

            crypto::scrypt::scrypt(
                password.as_bytes(),
                params.salt.as_bytes(),
                &crypto::scrypt::ScryptParams::new(log2_int(params.n) as u8, params.r, params.p),
                dk.as_mut_bytes(),
            );
            dk
        }
    }
}

// TODO: what says IV _must_ be 4 bytes?
fn get_iv(bytes: &[u8]) -> Result<[u8; IV_SIZE], Error> {
    if bytes.len() == IV_SIZE {
        let mut iv = [0; IV_SIZE];
        iv.copy_from_slice(bytes);
        Ok(iv)
    } else {
        Err(Error::IncorrectIvSize {
            expected: IV_SIZE,
            len: bytes.len(),
        })
    }
}

/// Compute floor of log2 of a u32.
fn log2_int(x: u32) -> u32 {
    if x == 0 {
        return 0;
    }
    31 - x.leading_zeros()
}

/*
#[cfg(test)]
mod tests {
    use super::*;

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

        let keystore = KeystoreBuilder::new(&keypair, password()).unwrap().build();

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

    // Test cases taken from:
    //
    // https://github.com/CarlBeek/EIPs/blob/bls_keystore/EIPS/eip-2335.md#test-cases
    #[test]
    fn eip_2335_test_vectors() {
        let expected_secret = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        let password: Password = "testpassword".into();
        let scrypt_test_vector = r#"
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

        let pbkdf2_test_vector = r#"
            {
            "crypto": {
                "kdf": {
                    "function": "pbkdf2",
                    "params": {
                        "dklen": 32,
                        "c": 262144,
                        "prf": "hmac-sha256",
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                    },
                    "message": ""
                },
                "checksum": {
                    "function": "sha256",
                    "params": {},
                    "message": "18b148af8e52920318084560fd766f9d09587b4915258dec0676cba5b0da09d8"
                },
                "cipher": {
                    "function": "aes-128-ctr",
                    "params": {
                        "iv": "264daa3f303d7259501c93d997d84fe6"
                    },
                    "message": "a9249e0ca7315836356e4c7440361ff22b9fe71e2e2ed34fc1eb03976924ed48"
                }
            },
            "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
            "path": "m/12381/60/0/0",
            "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
            "version": 4
        }
        "#;
        let test_vectors = vec![scrypt_test_vector, pbkdf2_test_vector];
        for test in test_vectors {
            let keystore: Keystore = serde_json::from_str(test).unwrap();
            let keypair = keystore.decrypt_keypair(password.clone()).unwrap();
            let expected_sk = hex::decode(expected_secret).unwrap();
            assert_eq!(keypair.sk.as_raw().as_bytes(), expected_sk)
        }
    }

    #[test]
    fn json_invalid_version() {
        let vector = r#"
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
            "version": 5
        }
        "#;

        match Keystore::from_json_str(&vector) {
            Err(Error::InvalidJson(_)) => {}
            _ => panic!("expected invalid json error"),
        }
    }

    #[test]
    fn json_bad_checksum() {
        let vector = r#"
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
                    "message": "149aafa27b041f3523c53d7acba1905fa6b1c90f9fef137568101f44b531a3cd"
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

        assert_eq!(
            Keystore::from_json_str(&vector)
                .unwrap()
                .decrypt_keypair("testpassword".into())
                .err()
                .unwrap(),
            Error::InvalidPassword
        );
    }

    #[test]
    fn json_invalid_kdf_function() {
        let vector = r#"
            {
            "crypto": {
                "kdf": {
                    "function": "not-scrypt",
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

        match Keystore::from_json_str(&vector) {
            Err(Error::InvalidJson(_)) => {}
            _ => panic!("expected invalid json error"),
        }
    }

    #[test]
    fn json_invalid_missing_scrypt_param() {
        let vector = r#"
            {
            "crypto": {
                "kdf": {
                    "function": "scrypt",
                    "params": {
                        "dklen": 32,
                        "n": 262144,
                        "p": 1,
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

        match Keystore::from_json_str(&vector) {
            Err(Error::InvalidJson(_)) => {}
            _ => panic!("expected invalid json error"),
        }
    }

    #[test]
    fn json_invalid_additional_scrypt_param() {
        let vector = r#"
            {
            "crypto": {
                "kdf": {
                    "function": "scrypt",
                    "params": {
                        "dklen": 32,
                        "n": 262144,
                        "p": 1,
                        "r": 8,
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
                        "cats": 42
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

        match Keystore::from_json_str(&vector) {
            Err(Error::InvalidJson(_)) => {}
            _ => panic!("expected invalid json error"),
        }
    }

    #[test]
    fn json_invalid_checksum_function() {
        let vector = r#"
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
                    "function": "not-sha256",
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

        match Keystore::from_json_str(&vector) {
            Err(Error::InvalidJson(_)) => {}
            _ => panic!("expected invalid json error"),
        }
    }

    #[test]
    fn json_invalid_checksum_params() {
        let vector = r#"
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
                    "params": {
                        "cats": "lol"
                    },
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

        match Keystore::from_json_str(&vector) {
            Err(Error::InvalidJson(_)) => {}
            _ => panic!("expected invalid json error"),
        }
    }

    #[test]
    fn json_invalid_cipher_function() {
        let vector = r#"
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
                    "function": "not-aes-128-ctr",
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

        match Keystore::from_json_str(&vector) {
            Err(Error::InvalidJson(_)) => {}
            _ => panic!("expected invalid json error"),
        }
    }

    #[test]
    fn json_invalid_additional_cipher_param() {
        let vector = r#"
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
                        "iv": "264daa3f303d7259501c93d997d84fe6",
                        "cat": 42
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

        match Keystore::from_json_str(&vector) {
            Err(Error::InvalidJson(_)) => {}
            _ => panic!("expected invalid json error"),
        }
    }

    #[test]
    fn json_invalid_missing_cipher_param() {
        let vector = r#"
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
                    "params": {},
                    "message": "54ecc8863c0550351eee5720f3be6a5d4a016025aa91cd6436cfec938d6a8d30"
                }
            },
            "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
            "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
            "path": "",
            "version": 4
        }
        "#;

        match Keystore::from_json_str(&vector) {
            Err(Error::InvalidJson(_)) => {}
            _ => panic!("expected invalid json error"),
        }
    }

    #[test]
    fn json_invalid_missing_pubkey() {
        let vector = r#"
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
            "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
            "path": "",
            "version": 4
        }
        "#;

        match Keystore::from_json_str(&vector) {
            Err(Error::InvalidJson(_)) => {}
            _ => panic!("expected invalid json error"),
        }
    }

    #[test]
    fn json_invalid_missing_path() {
        let vector = r#"
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
            "version": 4
        }
        "#;

        match Keystore::from_json_str(&vector) {
            Err(Error::InvalidJson(_)) => {}
            _ => panic!("expected invalid json error"),
        }
    }

    #[test]
    fn json_invalid_missing_version() {
        let vector = r#"
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
            "path": ""
        }
        "#;

        match Keystore::from_json_str(&vector) {
            Err(Error::InvalidJson(_)) => {}
            _ => panic!("expected invalid json error"),
        }
    }
}
*/
