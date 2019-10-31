use crate::cipher::{Aes128Ctr, Cipher, CipherMessage};
use crate::kdf::{Kdf, Pbkdf2, Prf};
use crypto::digest::Digest;
use crypto::sha2::Sha256;

use rand::prelude::*;

#[derive(Debug, PartialEq, Clone)]
pub struct Checksum(String);

/// Crypto
pub struct Crypto<K: Kdf, C: Cipher> {
    /// Key derivation function parameters
    pub kdf: K,
    /// Checksum for password verification
    pub checksum: Checksum,
    /// CipherParams parameters
    pub cipher: CipherMessage<C>,
}

impl<K: Kdf, C: Cipher> Crypto<K, C> {
    pub fn encrypt(password: String, secret: &[u8], kdf: K, cipher: C) -> Self {
        // Generate derived key
        let derived_key = kdf.derive_key(&password);
        // Encrypt secret
        let cipher_message = cipher.encrypt(&derived_key[0..16], secret);

        // Generate checksum
        let mut pre_image: Vec<u8> = derived_key[16..32].to_owned(); // last 16 bytes of decryption key
        pre_image.append(&mut cipher_message.clone());
        // create a Sha256 object
        let mut hasher = Sha256::new();
        hasher.input(&pre_image);
        // read hash digest
        let checksum = hasher.result_str();
        Crypto {
            kdf,
            checksum: Checksum(checksum),
            cipher: CipherMessage {
                cipher,
                message: cipher_message,
            },
        }
    }

    pub fn decrypt(&self, password: String) -> Vec<u8> {
        // Genrate derived key
        let derived_key = self.kdf.derive_key(&password);
        // Regenerate checksum
        let mut pre_image: Vec<u8> = derived_key[16..32].to_owned();
        pre_image.append(&mut self.cipher.message.clone());
        // create a Sha256 object
        let mut hasher = Sha256::new();
        hasher.input(&pre_image);
        // read hash digest
        let checksum = hasher.result_str();
        debug_assert_eq!(checksum, self.checksum.0);
        let secret = self
            .cipher
            .cipher
            .decrypt(&derived_key[0..16], &self.cipher.message);
        return secret;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector() {
        let secret_str = "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d";
        let salt_str = "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3";
        let iv_str = "264daa3f303d7259501c93d997d84fe6";
        let password = "testpassword".to_string();

        let salt = hex::decode(salt_str).unwrap();
        let iv = hex::decode(iv_str).unwrap();
        let kdf = Pbkdf2 {
            c: 262144,
            dklen: 32,
            prf: Prf::HmacSha256,
            salt: salt.to_vec(),
        };
        let cipher = Aes128Ctr { iv: iv };
        let secret = hex::decode(secret_str).unwrap();
        let crypto = Crypto::encrypt(password.clone(), &secret, kdf, cipher);
        println!("Cipher is {:?}", hex::encode(crypto.cipher.message.clone()));
        println!("Checksum is {:?}", crypto.checksum);
        let recovered_secret = crypto.decrypt(password);
        let recovered_secret_str = hex::encode(recovered_secret);
        println!("Secret is {:?}", recovered_secret_str);
        assert_eq!(recovered_secret_str, secret_str);
    }
}
