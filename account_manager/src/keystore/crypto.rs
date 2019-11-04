use crate::keystore::checksum::{Checksum, ChecksumModule};
use crate::keystore::cipher::{Cipher, CipherModule};
use crate::keystore::kdf::{Kdf, KdfModule};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Crypto {
    pub kdf: KdfModule,
    pub checksum: ChecksumModule,
    pub cipher: CipherModule,
}

impl Crypto {
    pub fn encrypt(password: String, secret: &[u8], kdf: Kdf, cipher: Cipher) -> Self {
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
        Crypto {
            kdf: KdfModule {
                function: kdf.function(),
                params: kdf.clone(),
                message: "".to_string(),
            },
            checksum: ChecksumModule {
                function: Checksum::function(),
                params: (),
                message: checksum,
            },
            cipher: CipherModule {
                function: cipher.function(),
                params: cipher.clone(),
                message: hex::encode(cipher_message),
            },
        }
    }

    pub fn decrypt(&self, password: String) -> Vec<u8> {
        // Genrate derived key
        let derived_key = match &self.kdf.params {
            Kdf::Pbkdf2(pbkdf2) => pbkdf2.derive_key(&password),
            Kdf::Scrypt(scrypt) => scrypt.derive_key(&password),
        };
        // Regenerate checksum
        let mut pre_image: Vec<u8> = derived_key[16..32].to_owned();
        pre_image.append(&mut hex::decode(self.cipher.message.clone()).unwrap());
        let checksum = Checksum::gen_checksum(&pre_image);
        debug_assert_eq!(checksum, self.checksum.message);
        let secret = match &self.cipher.params {
            Cipher::Aes128Ctr(cipher) => cipher.decrypt(
                &derived_key[0..16],
                &hex::decode(self.cipher.message.clone()).unwrap(),
            ),
        };
        return secret;
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
            hex::decode("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
                .unwrap();
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

        let keystore = Crypto::encrypt(password.clone(), &secret, kdf, cipher);
        let json = serde_json::to_string(&keystore).unwrap();
        println!("{}", json);

        let recovered_keystore: Crypto = serde_json::from_str(&json).unwrap();
        let recovered_secret = recovered_keystore.decrypt(password);

        assert_eq!(recovered_secret, secret);
    }

    #[test]
    fn test_scrypt() {
        let secret =
            hex::decode("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
                .unwrap();
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

        let keystore = Crypto::encrypt(password.clone(), &secret, kdf, cipher);
        let json = serde_json::to_string(&keystore).unwrap();
        println!("{}", json);

        let recovered_keystore: Crypto = serde_json::from_str(&json).unwrap();
        let recovered_secret = recovered_keystore.decrypt(password);

        assert_eq!(recovered_secret, secret);
    }
}
