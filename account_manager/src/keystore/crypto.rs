use crate::keystore::checksum::{Checksum, ChecksumModule};
use crate::keystore::cipher::{Cipher, CipherModule};
use crate::keystore::kdf::{Kdf, KdfModule};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Crypto {
    pub kdf: KdfModule,
    pub checksum: ChecksumModule,
    pub cipher: CipherModule,
}

impl Crypto {
    pub fn encrypt(
        password: String,
        secret: &[u8],
        kdf: Kdf,
        cipher: Cipher,
    ) -> Result<Self, String> {
        // Generate derived key
        let derived_key = match &kdf {
            Kdf::Pbkdf2(pbkdf2) => pbkdf2.derive_key(&password),
            Kdf::Scrypt(scrypt) => scrypt.derive_key(&password),
        };
        // Encrypt secret
        let cipher_message = match &cipher {
            Cipher::Aes128Ctr(cipher) => cipher.encrypt(&derived_key[0..16], secret),
        };
        // Generate checksum
        let mut pre_image: Vec<u8> = derived_key[16..32].to_owned(); // last 16 bytes of decryption key
        pre_image.append(&mut cipher_message.clone());
        let checksum = Checksum::gen_checksum(&pre_image);
        Ok(Crypto {
            kdf: KdfModule {
                function: kdf.function(),
                params: kdf.clone(),
                message: "".to_string(),
            },
            checksum: ChecksumModule {
                function: Checksum::function(),
                params: BTreeMap::new(),
                message: checksum,
            },
            cipher: CipherModule {
                function: cipher.function(),
                params: cipher.clone(),
                message: hex::encode(cipher_message),
            },
        })
    }

    pub fn decrypt(&self, password: String) -> Result<Vec<u8>, String> {
        // Genrate derived key
        let derived_key = match &self.kdf.params {
            Kdf::Pbkdf2(pbkdf2) => pbkdf2.derive_key(&password),
            Kdf::Scrypt(scrypt) => scrypt.derive_key(&password),
        };
        // Regenerate checksum
        let mut pre_image: Vec<u8> = derived_key[16..32].to_owned();
        pre_image.append(
            &mut hex::decode(self.cipher.message.clone())
                .map_err(|e| format!("Cipher message should be in hex: {}", e))?,
        );
        let checksum = Checksum::gen_checksum(&pre_image);
        debug_assert_eq!(checksum, self.checksum.message);
        let secret = match &self.cipher.params {
            Cipher::Aes128Ctr(cipher) => cipher.decrypt(
                &derived_key[0..16],
                &hex::decode(self.cipher.message.clone())
                    .map_err(|e| format!("Cipher message should be in hex: {}", e))?,
            ),
        };
        Ok(secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::cipher::{Aes128Ctr, Cipher};
    use crate::keystore::kdf::{Kdf, Pbkdf2, Prf, Scrypt};

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
        let password = "testpassword".to_string();

        let kdf = Kdf::Pbkdf2(Pbkdf2 {
            dklen: 32,
            c: 262144,
            prf: Prf::HmacSha256,
            salt: salt,
        });

        let cipher = Cipher::Aes128Ctr(Aes128Ctr {
            iv: from_slice(&iv),
        });

        let keystore = Crypto::encrypt(password.clone(), &secret, kdf, cipher).unwrap();

        assert_eq!(expected_checksum, keystore.checksum.message);
        assert_eq!(expected_cipher, keystore.cipher.message);

        let json = serde_json::to_string(&keystore).unwrap();
        println!("{}", json);

        let recovered_keystore: Crypto = serde_json::from_str(&json).unwrap();
        let recovered_secret = recovered_keystore.decrypt(password).unwrap();

        assert_eq!(secret, recovered_secret);
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
        let password = "testpassword".to_string();

        let kdf = Kdf::Scrypt(Scrypt {
            dklen: 32,
            n: 262144,
            r: 8,
            p: 1,
            salt: salt,
        });

        let cipher = Cipher::Aes128Ctr(Aes128Ctr {
            iv: from_slice(&iv),
        });

        let keystore = Crypto::encrypt(password.clone(), &secret, kdf, cipher).unwrap();

        assert_eq!(expected_checksum, keystore.checksum.message);
        assert_eq!(expected_cipher, keystore.cipher.message);

        let json = serde_json::to_string(&keystore).unwrap();
        println!("{}", json);

        let recovered_keystore: Crypto = serde_json::from_str(&json).unwrap();
        let recovered_secret = recovered_keystore.decrypt(password).unwrap();

        assert_eq!(secret, recovered_secret);
    }
}
