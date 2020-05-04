mod checksum;
mod cipher;
mod crypto;
mod kdf;

use crate::cipher::Cipher;
use crate::crypto::Crypto;
use crate::kdf::Kdf;
use bls::{Keypair, PublicKey, SecretKey};
use hex::FromHexError;
use serde::{Deserialize, Serialize};
use serde_repr::*;
use ssz::DecodeError;
use uuid::Uuid;

pub use crate::crypto::Password;

/// The byte-length of a BLS secret key.
const SECRET_KEY_LEN: usize = 32;

/// Version for `Keystore`.
#[derive(Debug, Clone, PartialEq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum Version {
    V4 = 4,
}

impl Default for Version {
    fn default() -> Self {
        Version::V4
    }
}

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidSecretKeyLen { len: usize, expected: usize },
    InvalidCipherMessageHex(FromHexError),
    InvalidPassword,
    InvalidSecretKeyBytes(DecodeError),
    PublicKeyMismatch,
    EmptyPassword,
    UnableToSerialize,
    InvalidJson,
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
            Ok(Self {
                keypair,
                password,
                kdf: <_>::default(),
                cipher: <_>::default(),
                uuid: Uuid::new_v4(),
            })
        }
    }

    /// Consumes `self`, returning a `Keystore`.
    pub fn build(self) -> Keystore {
        Keystore::new(
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
    crypto: Crypto,
    uuid: Uuid,
    path: String,
    pubkey: String,
    version: Version,
}

impl Keystore {
    /// Generate `Keystore` object for a BLS12-381 secret key from a
    /// keypair and password.
    fn new(keypair: &Keypair, password: Password, kdf: Kdf, cipher: Cipher, uuid: Uuid) -> Self {
        let crypto = Crypto::encrypt(password, &keypair.sk.as_raw().as_bytes(), kdf, cipher);

        Keystore {
            crypto,
            uuid,
            // TODO: Implement `path` according to
            // https://github.com/CarlBeek/EIPs/blob/bls_path/EIPS/eip-2334.md
            // For now, `path` is set to en empty string.
            path: String::new(),
            pubkey: keypair.pk.as_hex_string()[2..].to_string(),
            version: Version::default(),
        }
    }

    /// Regenerate a BLS12-381 `Keypair` from `self` and the correct password.
    ///
    /// ## Errors
    ///
    /// - The provided password is incorrect.
    /// - The keystore is badly formed.
    pub fn decrypt_keypair(&self, password: Password) -> Result<Keypair, Error> {
        // Decrypt cipher-text into plain-text.
        let sk_bytes = self.crypto.decrypt(password)?;

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
        if pk.as_hex_string()[2..].to_string() != self.pubkey {
            return Err(Error::PublicKeyMismatch);
        }

        Ok(Keypair { sk, pk })
    }

    /// Returns the UUID for the keystore.
    pub fn uuid(&self) -> &Uuid {
        &self.uuid
    }

    /// Returns `self` encoded as a JSON object.
    pub fn to_json_string(&self) -> Result<String, Error> {
        serde_json::to_string(self).map_err(|_| Error::UnableToSerialize)
    }

    /// Returns `self` encoded as a JSON object.
    pub fn from_json_str(json_string: &str) -> Result<Self, Error> {
        serde_json::from_str(json_string).map_err(|_| Error::InvalidJson)
    }
}

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

        assert_eq!(
            Keystore::from_json_str(&vector).err().unwrap(),
            Error::InvalidJson
        );
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
}
