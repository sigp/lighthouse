use crate::checksum::{ChecksumModule, Sha256Checksum};
use crate::cipher::{Cipher, CipherModule, PlainText};
use crate::kdf::{Kdf, KdfModule};
use crate::Error;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

#[derive(Zeroize, Clone, PartialEq)]
#[zeroize(drop)]
pub struct Password(String);

impl fmt::Display for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "******")
    }
}
impl Password {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[cfg(test)]
impl From<String> for Password {
    fn from(s: String) -> Password {
        Password(s)
    }
}

#[cfg(test)]
impl<'a> From<&'a str> for Password {
    fn from(s: &'a str) -> Password {
        Password::from(String::from(s))
    }
}

/// Crypto module for keystore.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Crypto {
    pub kdf: KdfModule,
    pub checksum: ChecksumModule,
    pub cipher: CipherModule,
}

impl Crypto {
    /// Generate crypto module for `Keystore` given the password,
    /// secret to encrypt, kdf params and cipher params.
    pub fn encrypt(password: Password, secret: &[u8], kdf: Kdf, cipher: Cipher) -> Self {
        // Generate derived key
        let derived_key = match &kdf {
            Kdf::Pbkdf2(pbkdf2) => pbkdf2.derive_key(password.as_str()),
            Kdf::Scrypt(scrypt) => scrypt.derive_key(password.as_str()),
        };
        // Encrypt secret
        let cipher_message: Vec<u8> = match &cipher {
            Cipher::Aes128Ctr(cipher) => cipher.encrypt(derived_key.aes_key(), secret),
        };

        Crypto {
            kdf: KdfModule {
                function: kdf.function(),
                params: kdf.clone(),
                message: "".to_string(),
            },
            checksum: ChecksumModule {
                function: Sha256Checksum::function(),
                params: serde_json::Value::Object(serde_json::Map::default()),
                message: Sha256Checksum::generate(&derived_key, &cipher_message),
            },
            cipher: CipherModule {
                function: cipher.function(),
                params: cipher.clone(),
                message: hex::encode(cipher_message),
            },
        }
    }

    /// Recover the secret present in the Keystore given the correct password.
    ///
    /// An error will be returned if `cipher.message` is not in hex format or
    /// if password is incorrect.
    pub fn decrypt(&self, password: Password) -> Result<PlainText, Error> {
        let cipher_message =
            hex::decode(self.cipher.message.clone()).map_err(Error::InvalidCipherMessageHex)?;

        // Generate derived key
        let derived_key = match &self.kdf.params {
            Kdf::Pbkdf2(pbkdf2) => pbkdf2.derive_key(password.as_str()),
            Kdf::Scrypt(scrypt) => scrypt.derive_key(password.as_str()),
        };

        // Mismatching `password` indicates an invalid password.
        if Sha256Checksum::generate(&derived_key, &cipher_message) != self.checksum.message {
            return Err(Error::InvalidPassword);
        }

        let secret = match &self.cipher.params {
            Cipher::Aes128Ctr(cipher) => cipher.decrypt(&derived_key.aes_key(), &cipher_message),
        };

        Ok(secret)
    }
}

// Test cases taken from https://github.com/CarlBeek/EIPs/blob/bls_keystore/EIPS/eip-2335.md#test-cases
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::{Aes128Ctr, Cipher};
    use crate::kdf::{Kdf, Pbkdf2, Prf, Scrypt};

    fn from_slice(bytes: &[u8]) -> [u8; 16] {
        let mut array = [0; 16];
        let bytes = &bytes[..array.len()]; // panics if not enough data
        array.copy_from_slice(bytes);
        array
    }

    #[test]
    fn test_pbkdf2() {
        let secret =
            hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .unwrap();
        let expected_checksum = "18b148af8e52920318084560fd766f9d09587b4915258dec0676cba5b0da09d8";
        let expected_cipher = "a9249e0ca7315836356e4c7440361ff22b9fe71e2e2ed34fc1eb03976924ed48";
        let salt = hex::decode("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
            .unwrap();
        let iv = hex::decode("264daa3f303d7259501c93d997d84fe6").unwrap();
        let password: Password = "testpassword".into();

        let kdf = Kdf::Pbkdf2(Pbkdf2 {
            dklen: 32,
            c: 262144,
            prf: Prf::HmacSha256,
            salt,
        });

        let cipher = Cipher::Aes128Ctr(Aes128Ctr {
            iv: from_slice(&iv),
        });

        let keystore = Crypto::encrypt(password.clone(), &secret, kdf, cipher);

        assert_eq!(expected_checksum, keystore.checksum.message);
        assert_eq!(expected_cipher, keystore.cipher.message);

        let json = serde_json::to_string(&keystore).unwrap();

        let recovered_keystore: Crypto = serde_json::from_str(&json).unwrap();
        let recovered_secret = recovered_keystore.decrypt(password).unwrap();

        assert_eq!(secret, recovered_secret.as_bytes());
    }

    #[test]
    fn test_scrypt() {
        let secret =
            hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .unwrap();
        let expected_checksum = "149aafa27b041f3523c53d7acba1905fa6b1c90f9fef137568101f44b531a3cb";
        let expected_cipher = "54ecc8863c0550351eee5720f3be6a5d4a016025aa91cd6436cfec938d6a8d30";
        let salt = hex::decode("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
            .unwrap();
        let iv = hex::decode("264daa3f303d7259501c93d997d84fe6").unwrap();
        let password: Password = "testpassword".into();

        let kdf = Kdf::Scrypt(Scrypt {
            dklen: 32,
            n: 262144,
            r: 8,
            p: 1,
            salt,
        });

        let cipher = Cipher::Aes128Ctr(Aes128Ctr {
            iv: from_slice(&iv),
        });

        let keystore = Crypto::encrypt(password.clone(), &secret, kdf, cipher);

        assert_eq!(expected_checksum, keystore.checksum.message);
        assert_eq!(expected_cipher, keystore.cipher.message);

        let json = serde_json::to_string(&keystore).unwrap();

        let recovered_keystore: Crypto = serde_json::from_str(&json).unwrap();
        let recovered_secret = recovered_keystore.decrypt(password).unwrap();

        assert_eq!(secret, recovered_secret.as_bytes());
    }
}
