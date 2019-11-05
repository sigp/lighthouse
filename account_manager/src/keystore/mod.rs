mod checksum;
mod cipher;
mod crypto;
mod kdf;
mod module;
use crate::keystore::cipher::Cipher;
use crate::keystore::crypto::Crypto;
use crate::keystore::kdf::Kdf;
use bls::SecretKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Keystore {
    crypto: Crypto,
    uuid: Uuid,
    version: Version,
}

impl Keystore {
    pub fn to_keystore(secret_key: &SecretKey, password: String) -> Result<Keystore, String> {
        let crypto = Crypto::encrypt(
            password,
            &secret_key.as_raw().as_bytes(),
            Kdf::default(),
            Cipher::default(),
        )?;
        let uuid = Uuid::new_v4();
        let version = Version::default();
        Ok(Keystore {
            crypto,
            uuid,
            version,
        })
    }

    pub fn from_keystore(keystore_str: String, password: String) -> Result<SecretKey, String> {
        let keystore: Keystore = serde_json::from_str(&keystore_str)
            .map_err(|e| format!("Keystore file invalid: {}", e))?;
        let sk = keystore.crypto.decrypt(password)?;
        SecretKey::from_bytes(&sk).map_err(|e| format!("Invalid secret key {:?}", e))
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
        let keystore = Keystore::to_keystore(&keypair.sk, password.clone()).unwrap();

        let json_str = serde_json::to_string(&keystore).unwrap();
        println!("{}", json_str);

        let sk = Keystore::from_keystore(json_str, password).unwrap();
        assert_eq!(sk, keypair.sk);
    }
}
