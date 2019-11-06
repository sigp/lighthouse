mod checksum;
mod cipher;
mod crypto;
mod kdf;
use crate::keystore::cipher::Cipher;
use crate::keystore::crypto::Crypto;
use crate::keystore::kdf::Kdf;
use bls::{Keypair, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::PathBuf;
use uuid::Uuid;

/// Version for `Keystore`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Version {
    #[serde(rename = "4")]
    V4,
}

impl Default for Version {
    fn default() -> Self {
        Version::V4
    }
}

/// TODO: Implement `path` according to
/// https://github.com/ethereum/EIPs/blob/de52c7ef2e44f2ab95d6aa4b90245c3c969aaf9f/EIPS/eip-2334.md
/// For now, `path` is set to en empty string.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Keystore {
    crypto: Crypto,
    uuid: Uuid,
    path: String,
    version: Version,
}

impl Keystore {
    /// Generate `Keystore` object for a BLS12-381 secret key from a
    /// keypair and password. Optionally, provide params for kdf and cipher.
    pub fn to_keystore(
        keypair: &Keypair,
        password: String,
        kdf: Option<Kdf>,
        cipher: Option<Cipher>,
    ) -> Self {
        let crypto = Crypto::encrypt(
            password,
            &keypair.sk.as_raw().as_bytes(),
            kdf.unwrap_or_default(),
            cipher.unwrap_or_default(),
        );
        let uuid = Uuid::new_v4();
        let version = Version::default();
        let path = "".to_string();
        Keystore {
            crypto,
            uuid,
            path,
            version,
        }
    }

    /// Regenerate a BLS12-381 `Keypair` given the `Keystore` object and
    /// the correct password.
    ///
    /// An error is returned if the secret in the `Keystore` is not a valid
    /// BLS12-381 secret key or if the password provided is incorrect.
    pub fn from_keystore(&self, password: String) -> Result<Keypair, String> {
        let sk = SecretKey::from_bytes(&self.crypto.decrypt(password)?)
            .map_err(|e| format!("Invalid secret key in keystore {:?}", e))?;
        let pk = PublicKey::from_secret_key(&sk);
        Ok(Keypair { sk, pk })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls::Keypair;
    #[test]
    fn test_keystore() {
        let keypair = Keypair::random();
        let password = "testpassword".to_string();
        let keystore = Keystore::to_keystore(&keypair, password.clone(), None, None);

        let json_str = serde_json::to_string(&keystore).unwrap();
        let recovered_keystore: Keystore = serde_json::from_str(&json_str).unwrap();
        let recovered_keypair = recovered_keystore.from_keystore(password).unwrap();
        assert_eq!(keypair, recovered_keypair);
    }
}
